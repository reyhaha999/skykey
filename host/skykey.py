#!/usr/bin/env python3
"""
SkyKey host program.

The chip is a login-code key: it holds a secret and makes one-time login
codes (TOTP, RFC 6238) from it.  The secret is made from a photo of the sky
taken with your own camera: the sensor noise in that photo is randomness only
you have.

Enrollment (once): the chip hashes your sky photo (mixed with your computer's
own randomness) into a secret.  The secret is shown once, as a QR link for
your authenticator app, and loaded into the chip in HMAC's pre-mixed form.
After that the program forgets it.  Each login code is made on the chip: this
program only sends the time counter, which is public.

Everything that makes a hash goes through the chip.  Python's own hashlib is
only used by the tests, to check the chip's answers.

Usage:
    python3 skykey.py --port /dev/ttyUSB0 selftest
    python3 skykey.py --port /dev/ttyUSB0 enroll --image sky.jpg --name me@example.com
    python3 skykey.py --port /dev/ttyUSB0 code
    python3 skykey.py --port /dev/ttyUSB0 wipe
    python3 skykey.py --port /dev/ttyUSB0 sha1 "hello"
    python3 skykey.py --port /dev/ttyUSB0 totp --secret JBSWY3DPEHPK3PXP
"""

import argparse
import base64
import os
import sys
import time
import urllib.parse

IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
M32 = 0xFFFFFFFF


def rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & M32


# ---------------------------------------------------------------------------
# What the computer does around the chip.
#
# The chip runs the 80 SHA-1 rounds.  The computer
#   1. expands the 64-byte block into 80 message words (a few XORs),
#   2. turns the hash state into the five starting values the rounds need,
#   3. adds the chip's answer back into the hash state.
# ---------------------------------------------------------------------------


def expand(block: bytes):
    w = [int.from_bytes(block[4 * i : 4 * i + 4], "big") for i in range(16)]
    for t in range(16, 80):
        w.append(rol(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1))
    return w


def start_values(state):
    h = state
    return [h[0], h[1], rol(h[2], 2), rol(h[3], 2), rol(h[4], 2)]


def finish(state, raw):
    h = state
    return tuple(
        (x + y) & M32
        for x, y in zip(h, [raw[0], raw[1], rol(raw[2], 30), rol(raw[3], 30), rol(raw[4], 30)])
    )


def words_to_bytes(words) -> bytes:
    return b"".join(x.to_bytes(4, "big") for x in words)


def bytes_to_words(data: bytes):
    return [int.from_bytes(data[i : i + 4], "big") for i in range(0, len(data), 4)]


def chip_request(state, block: bytes) -> bytes:
    """The 340 bytes that follow the 'B' command."""
    return words_to_bytes(start_values(state)) + words_to_bytes(expand(block))


def chip_result(state, reply: bytes):
    """Turn the chip's 20-byte reply into the new hash state."""
    return finish(state, bytes_to_words(reply))


def state_bytes(state) -> bytes:
    return words_to_bytes(state)


# ---------------------------------------------------------------------------
# Hash recipes.  Each one is a generator that yields (state, block) and is sent
# back the new state.  That lets the very same recipe run against a real serial
# port (drive) or against a simulated chip (adrive in the tests).
# ---------------------------------------------------------------------------


def pad_blocks(data: bytes, prefix_len: int = 0):
    """SHA-1 padding.  prefix_len is how many bytes were already hashed (a multiple of 64)."""
    total = prefix_len + len(data)
    padded = data + b"\x80"
    padded += b"\x00" * ((56 - len(padded)) % 64)
    padded += (total * 8).to_bytes(8, "big")
    return [padded[i : i + 64] for i in range(0, len(padded), 64)]


def sha1_gen(data: bytes, prefix_len: int = 0):
    state = IV
    for blk in pad_blocks(data, prefix_len):
        state = yield (state, blk)
    return state_bytes(state)


def hmac_gen(key: bytes, msg: bytes):
    if len(key) > 64:
        key = yield from sha1_gen(key)
    key = key.ljust(64, b"\x00")
    ipad = bytes(x ^ 0x36 for x in key)
    opad = bytes(x ^ 0x5C for x in key)

    state = yield (IV, ipad)
    for blk in pad_blocks(msg, 64):
        state = yield (state, blk)
    inner = state_bytes(state)

    state = yield (IV, opad)
    for blk in pad_blocks(inner, 64):
        state = yield (state, blk)
    return state_bytes(state)


def truncate(mac: bytes, digits: int = 6) -> str:
    """RFC 4226 dynamic truncation."""
    off = mac[19] & 0x0F
    code = int.from_bytes(mac[off : off + 4], "big") & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def totp_gen(secret: bytes, t: int, step: int = 30, digits: int = 6):
    counter = (t // step).to_bytes(8, "big")
    mac = yield from hmac_gen(secret, counter)
    return truncate(mac, digits)


# ---------------------------------------------------------------------------
# Keyed recipes: the chip holds the key.
#
# HMAC starts both of its hashes with one block made only from the key
# (key XOR ipad, key XOR opad).  The hash states after those two blocks are
# the key in pre-mixed form; they are what gets loaded into the chip.  After
# that, a code needs only public blocks: the time counter (inner hash) and the
# inner result (outer hash).  The chip starts each from its stored state and
# does the final addition itself, so the stored states never come back out.
# ---------------------------------------------------------------------------


def key_states_gen(key: bytes):
    """The two pre-mixed states for an HMAC key (made with chip hashes)."""
    if len(key) > 64:
        key = yield from sha1_gen(key)
    key = key.ljust(64, b"\x00")
    inner = yield (IV, bytes(x ^ 0x36 for x in key))
    outer = yield (IV, bytes(x ^ 0x5C for x in key))
    return inner, outer


def key_load_request(inner, outer) -> bytes:
    """The 40 bytes that follow the 'L' command."""
    return words_to_bytes(start_values(inner)) + words_to_bytes(start_values(outer))


def keyed_hmac_gen(msg: bytes):
    """HMAC with the key the chip holds.

    Yields ("I", block), ("O", block) or (state, block) requests; the first
    two run on the chip's stored inner / outer state.  Any later inner blocks
    (messages over 55 bytes) continue from a state that is no longer secret.
    """
    blocks = pad_blocks(msg, 64)
    state = yield ("I", blocks[0])
    for blk in blocks[1:]:
        state = yield (state, blk)
    (outer_blk,) = pad_blocks(state_bytes(state), 64)
    state = yield ("O", outer_blk)
    return state_bytes(state)


def keyed_totp_gen(t: int, step: int = 30, digits: int = 6):
    counter = (t // step).to_bytes(8, "big")
    mac = yield from keyed_hmac_gen(counter)
    return truncate(mac, digits)


def keyed_request(block: bytes) -> bytes:
    """The 320 bytes that follow an 'I' or 'O' command."""
    return words_to_bytes(expand(block))


def drive(gen, chip):
    """Run a recipe against a synchronous chip object."""
    try:
        req = next(gen)
        while True:
            req = gen.send(chip.compress(*req))
    except StopIteration as stop:
        return stop.value


async def adrive(gen, chip):
    """Same as drive(), for an async chip object (used by the simulation tests)."""
    try:
        req = next(gen)
        while True:
            req = gen.send(await chip.compress(*req))
    except StopIteration as stop:
        return stop.value


# ---------------------------------------------------------------------------
# The real chip over a serial port.
# ---------------------------------------------------------------------------


class SkyKeyChip:
    def __init__(self, port: str, baud: int = 115200):
        import serial  # pip install pyserial

        self.ser = serial.Serial(port, baud, timeout=5)
        self.ser.reset_input_buffer()
        if not self.ping():
            raise RuntimeError("the chip did not answer; check the wiring and the 10 MHz clock")

    def _expect(self, n: int) -> bytes:
        data = self.ser.read(n)
        if len(data) != n:
            raise TimeoutError("the chip stopped answering")
        return data

    def ping(self) -> bool:
        self.ser.write(b"?")
        return self.ser.read(1) == b"K"

    def selftest(self) -> bool:
        self.ser.write(b"T")
        return self._expect(1) == b"P"

    def compress(self, state, block: bytes):
        """Run one 64-byte block through the chip; returns the new hash state.

        state "I" or "O" means: start from the key state the chip holds."""
        assert len(block) == 64
        if state in ("I", "O"):
            self.ser.write(state.encode() + keyed_request(block))
            return tuple(bytes_to_words(self._expect(20)))
        self.ser.write(b"B" + chip_request(state, block))
        return chip_result(state, self._expect(20))

    def load_key(self, secret: bytes):
        inner, outer = drive(key_states_gen(secret), self)
        self.ser.write(b"L" + key_load_request(inner, outer))
        if self._expect(1) != b"L":
            raise RuntimeError("the chip did not confirm the key load")

    def wipe(self):
        self.ser.write(b"Z")
        if self._expect(1) != b"Z":
            raise RuntimeError("the chip did not confirm the wipe")

    def code(self, t=None, step: int = 30, digits: int = 6) -> str:
        """A login code from the key the chip holds."""
        t = int(time.time()) if t is None else t
        return drive(keyed_totp_gen(t, step, digits), self)

    def sha1(self, data: bytes) -> bytes:
        return drive(sha1_gen(data), self)

    def hmac(self, key: bytes, msg: bytes) -> bytes:
        return drive(hmac_gen(key, msg), self)

    def totp(self, secret: bytes, t=None, step: int = 30, digits: int = 6) -> str:
        t = int(time.time()) if t is None else t
        return drive(totp_gen(secret, t, step, digits), self)


# ---------------------------------------------------------------------------
# Secret from the sky.
# ---------------------------------------------------------------------------


def make_secret(chip: SkyKeyChip, image: bytes, local_noise: bytes = b"") -> bytes:
    """Squeeze a 20-byte secret out of a sky photo, using the chip's hash.

    The photo should come from your own camera: its sensor noise is the
    randomness.  The computer's own randomness is mixed in as well, so the
    secret stays strong even if the photo were ever seen by someone else.
    """
    return chip.sha1(image + local_noise + time.time_ns().to_bytes(8, "little"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    p = sub.add_parser("enroll")
    p.add_argument("--image", required=True, help="a photo of the sky from your own camera")
    p.add_argument("--name", default="skykey")
    p.add_argument("--issuer", default="SkyKey")
    p = sub.add_parser("code")
    p.add_argument("--digits", type=int, default=6)
    sub.add_parser("wipe")
    p = sub.add_parser("sha1")
    p.add_argument("text")
    p = sub.add_parser("totp", help="code from a secret you type in (the key is not stored on the chip)")
    p.add_argument("--secret", required=True, help="base32 secret, like an authenticator app uses")
    p.add_argument("--digits", type=int, default=6)
    args = ap.parse_args()

    chip = SkyKeyChip(args.port)
    if args.cmd == "selftest":
        ok = chip.selftest()
        print("self-test:", "PASS" if ok else "FAIL")
        sys.exit(0 if ok else 1)
    if args.cmd == "enroll":
        with open(args.image, "rb") as f:
            image = f.read()
        secret = make_secret(chip, image, os.urandom(16))
        chip.load_key(secret)
        b32 = base64.b32encode(secret).decode().rstrip("=")
        label = urllib.parse.quote(f"{args.issuer}:{args.name}")
        print(f"sky photo: {len(image)} bytes from {args.image}")
        print("add this to your authenticator app (shown once):")
        print(f"otpauth://totp/{label}?secret={b32}&issuer={urllib.parse.quote(args.issuer)}&algorithm=SHA1&digits=6&period=30")
        del secret, b32
        print("first code from the chip:", chip.code())
    if args.cmd == "code":
        print(chip.code(digits=args.digits))
    if args.cmd == "wipe":
        chip.wipe()
        print("key wiped")
    if args.cmd == "sha1":
        print(chip.sha1(args.text.encode()).hex())
    if args.cmd == "totp":
        secret = base64.b32decode(args.secret.replace(" ", "").upper() + "=" * (-len(args.secret) % 8))
        print(chip.totp(secret, digits=args.digits))


if __name__ == "__main__":
    main()
