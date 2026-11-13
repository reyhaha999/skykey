<!---
This file is used to generate your project datasheet.
-->

## How it works

SkyKey is a login-code key: a chip that holds a secret and makes the six-digit one-time codes (TOTP, RFC 6238) that authenticator apps show. The secret is made from a photo of the sky taken with your own camera, whose sensor noise is randomness nobody else has.

Inside is a bit-serial SHA-1 engine, the hash behind HMAC and TOTP. SHA-1 turns a block of data into a 20-byte fingerprint by running 80 rounds of simple math on five 32-bit numbers. The chip does those rounds one bit at a time: the five numbers sit in a 192-bit loop of flip-flops that keeps circulating, and a single 1-bit adder, plus four carry flip-flops, does the additions as the bits go past.

**Where the key lives.** HMAC starts both of its hashes with one block made only from the key; the hash states after those blocks ("inner" and "outer") are the key in pre-mixed form. The chip stores the inner state in a second 192-bit loop that turns in step with the working loop. Every login code starts with a hash of the time counter from that state: the chip copies the stored state into the working loop, runs the 80 rounds, and does the final addition itself, reading the stored state straight from its loop. No command ever sends it back out, so no code can be made without the chip. The outer state stays with the computer; on its own it can't make a code.

**Enrollment.** The computer sends the sky photo through the chip's hash (mixed with the computer's own randomness) to make the secret, shows it once as a link for your authenticator app, loads the inner state into the chip, keeps the outer state, and forgets the secret.

**What the computer still does.** It expands each public block into the 80 message words SHA-1 needs and streams them in, and runs the outer hash on the chip's inner result.

Serial protocol (115,200 baud, 8N1, 10 MHz clock) on the demo board's standard serial pins, RX = ui[3] and TX = uo[4], so the board's RP2040 carries it over USB:

| Byte | Meaning |
|------|---------|
| `?`  | Replies `K` |
| `T`  | Built-in self-test: hashes a known block from an on-chip table and replies `P` or `F` |
| `L`  | Load the key: the 20-byte inner state; replies `L` |
| `I`  | Keyed hash from the stored state: 320 message-word bytes in, finished 20-byte hash out |
| `Z`  | Wipe the key; replies `Z` |
| `B`  | Plain hash, no key: 20 start-value bytes and 320 message-word bytes; replies with 20 bytes |

The 7-segment display shows H while hashing, P after a pass, F after a fail, and r (ready) when idle. Segment E doubles as the serial TX line; it rests high, and every letter shown uses it.

## How to test

Run `make -C test` (cocotb + Icarus) to check the chip against FIPS SHA-1, RFC 2202 HMAC and RFC 6238 TOTP vectors, with the key both on the computer and held on the chip, plus a wipe test and random blocks. On hardware, send `?` and expect `K`, then `T` and expect `P`. From a computer: `python host/skykey.py --port <port> selftest`, then `enroll --image sky.jpg`, then `code`. After the board loses power, `restore` reloads the key from a passphrase-locked backup saved at enrollment.

## Honest limits

This is a design demonstration, not a certified security key. The chip has no permanent memory, so the key is lost when power goes off; `restore` reloads it from the passphrase-locked backup made at enrollment (skip that backup with `--no-backup` and you enroll again instead), and it has no clock of its own (the computer supplies the time). Like any TOTP token, the secret is shared once with the service at enrollment. The chip accepts message words from the computer as given, so it relies on the strength of SHA-1's rounds rather than checking them.

## External hardware

The Tiny Tapeout demo board: its RP2040 provides the 10 MHz clock and the serial link over USB (RX ui[3], TX uo[4]), and its 7-segment display shows status. Any other USB-serial adapter wired to those two pins works too.
