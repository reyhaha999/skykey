#!/usr/bin/env python3
"""
SkyKey host program.

The chip is a SHA-1 hash engine.  This program does the rest: it pads
messages, builds HMAC and one-time login codes (TOTP, RFC 6238) out of
chip hashes, and feeds the chip a photo of the real sky to make a secret.

Everything that makes a hash goes through the chip.  Python's own hashlib is
only used by the tests, to check the chip's answers.

Usage:
    python3 skykey.py --port /dev/ttyUSB0 selftest
    python3 skykey.py --port /dev/ttyUSB0 sha1 "hello"
    python3 skykey.py --port /dev/ttyUSB0 totp --secret JBSWY3DPEHPK3PXP
    python3 skykey.py --port /dev/ttyUSB0 enroll --name me@example.com
"""

import argparse
import base64
import os
import sys
import time
import urllib.parse
import urllib.request

IV = bytes.fromhex("67452301EFCDAB8998BADCFE10325476C3D2E1F0")

SKY_URLS = [
    "https://sgo.fi/Data/RealTime/Kuvat/SOD.jpg",
    "https://astroweb.unisq.edu.au/ops/Allsky/image_29.jpg",
]


# ---------------------------------------------------------------------------
# Hash recipes.  Each one is a generator: it yields (block, first) requests and
# is sent back the chip's answer.  That lets the very same recipe run against a
# real serial port (drive) or against a simulated chip (adrive in the tests).
# ---------------------------------------------------------------------------


def pad_blocks(data: bytes, prefix_len: int = 0):
    """SHA-1 padding.  prefix_len is how many bytes were already hashed (a multiple of 64)."""
    total = prefix_len + len(data)
    padded = data + b"\x80"
    padded += b"\x00" * ((56 - len(padded)) % 64)
    padded += (total * 8).to_bytes(8, "big")
    return [padded[i : i + 64] for i in range(0, len(padded), 64)]


def sha1_gen(data: bytes, prefix_len: int = 0):
    """Hash `data`.  Yields ("reset",), ("block", b, want_digest)."""
    yield ("reset",)
    blocks = pad_blocks(data, prefix_len)
    digest = None
    for i, blk in enumerate(blocks):
        last = i == len(blocks) - 1
        digest = yield ("block", blk, last)
    return digest


def hmac_gen(key: bytes, msg: bytes):
    if len(key) > 64:
        key = yield from sha1_gen(key)
    key = key.ljust(64, b"\x00")
    ipad = bytes(x ^ 0x36 for x in key)
    opad = bytes(x ^ 0x5C for x in key)

    yield ("reset",)
    yield ("block", ipad, False)
    blocks = pad_blocks(msg, 64)
    inner = None
    for i, blk in enumerate(blocks):
        inner = yield ("block", blk, i == len(blocks) - 1)

    yield ("reset",)
    yield ("block", opad, False)
    blocks = pad_blocks(inner, 64)
    outer = None
    for i, blk in enumerate(blocks):
        outer = yield ("block", blk, i == len(blocks) - 1)
    return outer


def truncate(mac: bytes, digits: int = 6) -> str:
    """RFC 4226 dynamic truncation."""
    off = mac[19] & 0x0F
    code = int.from_bytes(mac[off : off + 4], "big") & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def totp_gen(secret: bytes, t: int, step: int = 30, digits: int = 6):
    counter = (t // step).to_bytes(8, "big")
    mac = yield from hmac_gen(secret, counter)
    return truncate(mac, digits)


def drive(gen, chip):
    """Run a recipe against a synchronous chip object."""
    try:
        req = next(gen)
        while True:
            if req[0] == "reset":
                chip.reset_state()
                answer = None
            else:
                answer = chip.compress(req[1], req[2])
            req = gen.send(answer)
    except StopIteration as stop:
        return stop.value


async def adrive(gen, chip):
    """Same as drive(), for an async chip object (used by the simulation tests)."""
    try:
        req = next(gen)
        while True:
            if req[0] == "reset":
                await chip.reset_state()
                answer = None
            else:
                answer = await chip.compress(req[1], req[2])
            req = gen.send(answer)
    except StopIteration as stop:
        return stop.value


# ---------------------------------------------------------------------------
# The real chip over a serial port.
# ---------------------------------------------------------------------------


class SkyKeyChip:
    def __init__(self, port: str, baud: int = 38400):
        import serial  # pip install pyserial

        self.ser = serial.Serial(port, baud, timeout=2)
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

    def reset_state(self):
        self.ser.write(b"I")
        assert self._expect(1) == b"K"

    def compress(self, block: bytes, want_digest: bool = True):
        assert len(block) == 64
        self.ser.write((b"B" if want_digest else b"b") + block)
        if want_digest:
            return self._expect(20)
        assert self._expect(1) == b"K"
        return None

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


def fetch_sky_image():
    errors = []
    for url in SKY_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "skykey", "Cache-Control": "no-cache"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                image = resp.read()
            if not image.startswith(b"\xff\xd8"):
                raise ValueError("not a JPEG image")
            return image, url
        except Exception as e:  # try the next camera
            errors.append(f"{url}: {e}")
    raise RuntimeError("; ".join(errors))


def make_secret(chip: SkyKeyChip, image: bytes, local_noise: bytes = b"") -> bytes:
    """Squeeze a 20-byte secret out of a sky photo, using the chip's hash.

    A public sky photo is public, so mix in noise only you have (for example a
    frame from your own camera, or os.urandom) before treating it as secret.
    """
    return chip.sha1(image + local_noise + time.time_ns().to_bytes(8, "little"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    p = sub.add_parser("sha1")
    p.add_argument("text")
    p = sub.add_parser("totp")
    p.add_argument("--secret", required=True, help="base32 secret, like an authenticator app uses")
    p.add_argument("--digits", type=int, default=6)
    p = sub.add_parser("enroll")
    p.add_argument("--name", default="skykey")
    p.add_argument("--issuer", default="SkyKey")
    args = ap.parse_args()

    chip = SkyKeyChip(args.port)
    if args.cmd == "selftest":
        ok = chip.selftest()
        print("self-test:", "PASS" if ok else "FAIL")
        sys.exit(0 if ok else 1)
    if args.cmd == "sha1":
        print(chip.sha1(args.text.encode()).hex())
    if args.cmd == "totp":
        secret = base64.b32decode(args.secret.replace(" ", "").upper() + "=" * (-len(args.secret) % 8))
        print(chip.totp(secret, digits=args.digits))
    if args.cmd == "enroll":
        image, url = fetch_sky_image()
        secret = make_secret(chip, image, os.urandom(16))
        b32 = base64.b32encode(secret).decode().rstrip("=")
        label = urllib.parse.quote(f"{args.issuer}:{args.name}")
        print(f"sky image: {len(image)} bytes from {url}")
        print(f"secret (base32): {b32}")
        print(f"otpauth://totp/{label}?secret={b32}&issuer={urllib.parse.quote(args.issuer)}&algorithm=SHA1&digits=6&period=30")
        print("first code:", chip.totp(secret))


if __name__ == "__main__":
    main()
