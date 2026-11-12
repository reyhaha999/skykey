# SPDX-FileCopyrightText: © 2026 Sehrey Kita
# SPDX-License-Identifier: Apache-2.0

"""
Tests for SkyKey.

The chip is driven exactly like real hardware: bytes go in and out over its
serial pins.  The hash recipes (padding, HMAC, one-time codes) are the same
code that the real host program uses (host/skykey.py), and every answer is
checked against Python's own hashlib/hmac and the official RFC test vectors.
"""

import hashlib
import hmac as pyhmac
import os
import sys

import cocotb
from cocotb.triggers import ClockCycles, FallingEdge, First, Timer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host"))
import skykey  # noqa: E402

GATES = os.environ.get("GATES", "no") == "yes"
BIT_NS = 8700  # one serial bit at 115,200 baud (87 clocks of 100 ns)
TIMEOUT_BITS = 12000


class SimChip:
    """The simulated chip, spoken to over its serial pins."""

    def __init__(self, dut):
        self.dut = dut

    async def send(self, data: bytes):
        for byte in data:
            self.dut.ui_in.value = 0x00  # start bit
            await Timer(BIT_NS, unit="ns")
            for i in range(8):
                self.dut.ui_in.value = (byte >> i) & 1
                await Timer(BIT_NS, unit="ns")
            self.dut.ui_in.value = 0x01  # stop bit
            await Timer(BIT_NS, unit="ns")

    async def recv(self, n: int) -> bytes:
        out = bytearray()
        for _ in range(n):
            edge = await First(FallingEdge(self.dut.serial_tx), Timer(TIMEOUT_BITS * BIT_NS, unit="ns"))
            assert not isinstance(edge, Timer) and self.dut.serial_tx.value == 0, "chip stopped answering"
            await Timer(BIT_NS * 3 // 2, unit="ns")
            byte = 0
            for i in range(8):
                byte |= int(self.dut.serial_tx.value) << i
                await Timer(BIT_NS, unit="ns")
            out.append(byte)
        return bytes(out)

    async def ask(self, data: bytes, n: int) -> bytes:
        """Send a command and collect the n-byte reply (listening starts first, since
        the chip begins answering while the last stop bit is still going by)."""
        listener = cocotb.start_soon(self.recv(n))
        await self.send(data)
        return await listener

    async def ping(self):
        return await self.ask(b"?", 1)

    async def compress(self, state, block: bytes):
        """Run one block through the chip; returns the new hash state.
        state "I" runs the block on the key state the chip holds."""
        if state == "I":
            reply = await self.ask(b"I" + skykey.keyed_request(block), 20)
            return tuple(skykey.bytes_to_words(reply))
        reply = await self.ask(b"B" + skykey.chip_request(state, block), 20)
        return skykey.chip_result(state, reply)

    async def load_key(self, secret: bytes):
        """Load the inner state into the chip; returns the outer state (kept by the host)."""
        inner, outer = await skykey.adrive(skykey.key_states_gen(secret), self)
        assert await self.ask(b"L" + skykey.key_load_request(inner), 1) == b"L"
        return outer

    async def wipe(self):
        assert await self.ask(b"Z", 1) == b"Z"


async def start_chip(dut) -> SimChip:
    dut.ena.value = 1
    dut.ui_in.value = 0x01
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 20)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 20)
    return SimChip(dut)


def seg_text(dut) -> str:
    v = int(dut.uo_out.value) & 0x7F
    return {0b1000000: "-", 0b1110011: "P", 0b1110001: "F", 0b1110110: "H"}.get(v, hex(v))


@cocotb.test()
async def test_ping_and_selftest(dut):
    """The chip answers '?', and its built-in self-test (hash 'abc') passes."""
    chip = await start_chip(dut)
    assert await chip.ping() == b"K"
    assert seg_text(dut) == "-"
    assert await chip.ask(b"T", 1) == b"P", "built-in self-test failed"
    assert seg_text(dut) == "P"


@cocotb.test()
async def test_sha1_known_answers(dut):
    """SHA-1 of several messages (empty, abc, one block, two blocks) matches hashlib."""
    chip = await start_chip(dut)
    messages = [
        b"abc",
        b"",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",  # FIPS 180 two-block message
        bytes(range(256)) * 1,
    ]
    if GATES:
        messages = messages[:1]
    for msg in messages:
        got = await skykey.adrive(skykey.sha1_gen(msg), chip)
        assert got == hashlib.sha1(msg).digest(), f"SHA-1 mismatch for {msg[:16]!r}..."
        dut._log.info(f"sha1 {len(msg)} bytes ok")


@cocotb.test()
async def test_hmac_rfc2202(dut):
    """HMAC-SHA1 against RFC 2202 test cases, including a key longer than a block."""
    chip = await start_chip(dut)
    cases = [
        (b"\x0b" * 20, b"Hi There", "b617318655057264e28bc0b6fb378c8ef146be00"),
        (b"Jefe", b"what do ya want for nothing?", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
        (b"\xaa" * 20, b"\xdd" * 50, "125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
        (
            b"\xaa" * 80,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
        ),
    ]
    if GATES:
        cases = cases[:1]
    for key, msg, want in cases:
        got = await skykey.adrive(skykey.hmac_gen(key, msg), chip)
        assert got.hex() == want, f"HMAC mismatch: {got.hex()} != {want}"
        assert got == pyhmac.new(key, msg, hashlib.sha1).digest()
        dut._log.info(f"hmac key={len(key)}B msg={len(msg)}B ok")


@cocotb.test()
async def test_totp_rfc6238(dut):
    """One-time login codes against the RFC 6238 SHA-1 test vectors (8 digits)."""
    chip = await start_chip(dut)
    secret = b"12345678901234567890"
    vectors = [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ]
    if GATES:
        vectors = vectors[:1]
    for t, want in vectors:
        got = await skykey.adrive(skykey.totp_gen(secret, t, digits=8), chip)
        assert got == want, f"TOTP at t={t}: {got} != {want}"
        dut._log.info(f"totp t={t} -> {got} ok")
    # and a normal 6-digit code (what an authenticator app shows)
    six = await skykey.adrive(skykey.totp_gen(secret, 59, digits=6), chip)
    assert six == "287082"


@cocotb.test()
async def test_random_blocks(dut):
    """Random blocks and random starting states match a software SHA-1 round model."""
    chip = await start_chip(dut)
    for _ in range(2 if GATES else 4):
        state = tuple(int.from_bytes(os.urandom(4), "big") for _ in range(5))
        block = os.urandom(64)
        got = await chip.compress(state, block)
        assert got == sw_compress(state, block), "chip and software model disagree"


RFC6238 = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@cocotb.test()
async def test_onchip_key_totp(dut):
    """Key held on the chip: login codes match RFC 6238, and the key survives
    other work (plain hashes) in between."""
    chip = await start_chip(dut)
    outer = await chip.load_key(b"12345678901234567890")
    vectors = RFC6238[:1] if GATES else RFC6238
    for t, want in vectors:
        got = await skykey.adrive(skykey.keyed_totp_gen(t, outer, digits=8), chip)
        assert got == want, f"on-chip key TOTP at t={t}: {got} != {want}"
        dut._log.info(f"on-chip key totp t={t} -> {got} ok")
    # a plain hash in between must not disturb the stored key
    assert await skykey.adrive(skykey.sha1_gen(b"abc"), chip) == hashlib.sha1(b"abc").digest()
    assert await skykey.adrive(skykey.keyed_totp_gen(59, outer, digits=6), chip) == "287082"


@cocotb.test()
async def test_onchip_key_hmac_rfc2202(dut):
    """HMAC with the key held on the chip, against RFC 2202 (including a key
    longer than a block and a message longer than a block)."""
    chip = await start_chip(dut)
    cases = [
        (b"\x0b" * 20, b"Hi There", "b617318655057264e28bc0b6fb378c8ef146be00"),
        (b"Jefe", b"what do ya want for nothing?", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
        (
            b"\xaa" * 80,
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
        ),
    ]
    if GATES:
        cases = cases[:1]
    for key, msg, want in cases:
        outer = await chip.load_key(key)
        got = await skykey.adrive(skykey.keyed_hmac_gen(msg, outer), chip)
        assert got.hex() == want, f"on-chip key HMAC mismatch: {got.hex()} != {want}"
        assert got == pyhmac.new(key, msg, hashlib.sha1).digest()
        dut._log.info(f"on-chip key hmac key={len(key)}B msg={len(msg)}B ok")


@cocotb.test()
async def test_wipe(dut):
    """'Z' wipes the key: codes stop matching until a key is loaded again."""
    chip = await start_chip(dut)
    secret = b"12345678901234567890"
    outer = await chip.load_key(secret)
    assert await skykey.adrive(skykey.keyed_totp_gen(59, outer, digits=8), chip) == "94287082"
    await chip.wipe()
    # after a wipe the stored state is zero
    blk = skykey.pad_blocks(b"x", 64)[0]
    got = await chip.compress("I", blk)
    assert got == sw_compress((0, 0, 0, 0, 0), blk), "wipe did not clear the key"
    outer = await chip.load_key(secret)
    assert await skykey.adrive(skykey.keyed_totp_gen(59, outer, digits=8), chip) == "94287082"


def sw_compress(state, block):
    """Plain software SHA-1 compression function (reference)."""
    w = skykey.expand(block)
    a, b, c, d, e = state
    for t in range(80):
        if t < 20:
            f, k = (b & c) | (~b & d), 0x5A827999
        elif t < 40:
            f, k = b ^ c ^ d, 0x6ED9EBA1
        elif t < 60:
            f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:
            f, k = b ^ c ^ d, 0xCA62C1D6
        a, b, c, d, e = (skykey.rol(a, 5) + f + e + k + w[t]) & 0xFFFFFFFF, a, skykey.rol(b, 30), c, d
    return tuple((x + y) & 0xFFFFFFFF for x, y in zip(state, (a, b, c, d, e)))
