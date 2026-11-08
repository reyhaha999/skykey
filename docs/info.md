<!---
This file is used to generate your project datasheet.
-->

## How it works

SkyKey is a tiny hardware engine for SHA-1, the scrambling function behind HMAC and the six-digit one-time login codes (TOTP, RFC 6238) that authenticator apps show.

SHA-1 turns a block of data into a 20-byte fingerprint by running 80 rounds of simple math on five 32-bit numbers. This chip does those rounds one bit at a time ("bit-serial"): the five numbers sit in a 192-bit loop of flip-flops that keeps circulating, and a single 1-bit adder, plus four carry flip-flops, does the additions as the bits go past. That is why the whole thing fits in a 1x2 tile (about 34% of the area).

A computer (or a microcontroller) does the bookkeeping that doesn't need to be secret or fast:

1. It expands the 16 message words into the 80 words SHA-1 needs.
2. It sends the chip the 20-byte starting value and all 80 expanded words (320 bytes) over serial (`B` command).
3. The chip runs the 80 rounds and sends back 20 bytes.
4. The computer does the final addition.

HMAC and TOTP are then just a few hash calls in a row; the host-side recipe lives in `host/skykey.py`. The chip holds no key and keeps no state between calls.

Serial protocol (115,200 baud, 8N1, 10 MHz clock):

| Byte | Meaning |
|------|---------|
| `?`  | Replies `K` |
| `T`  | Built-in self-test: hashes a known block from an on-chip table and replies `P` or `F` |
| `B`  | Then 20 start-value bytes and 320 message-word bytes; replies with 20 bytes |

The 7-segment display shows H while hashing, P after a pass, F after a fail, and a dash when idle.

## How to test

Run `make -C test` (cocotb + Icarus) to check the chip against FIPS SHA-1, RFC 2202 HMAC and RFC 6238 TOTP vectors plus random blocks. On hardware, send `?` and expect `K`, then `T` and expect `P`. `python host/skykey.py selftest` and `python host/skykey.py totp` do the same from a computer.

## Honest limits

This is a design demonstration, not a certified security key. The chip has no non-volatile memory and no clock of its own, and the secret key lives on the host, not the chip. Secrets are generated from camera noise mixed with the operating system's randomness.

## External hardware

A USB-serial adapter (or an RP2040/ESP32) wired to RX (ui[0]) and TX (uio[0]). Optional: a 7-segment display on uo[0..6].
