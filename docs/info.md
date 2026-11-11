<!---
This file is used to generate your project datasheet.
-->

## How it works

SkyKey is a login-code key: a chip that holds a secret and makes the six-digit one-time codes (TOTP, RFC 6238) that authenticator apps show. The secret is made from a photo of the sky taken with your own camera, whose sensor noise is randomness nobody else has.

Inside is a bit-serial SHA-1 engine, the hash behind HMAC and TOTP. SHA-1 turns a block of data into a 20-byte fingerprint by running 80 rounds of simple math on five 32-bit numbers. The chip does those rounds one bit at a time: the five numbers sit in a 192-bit loop of flip-flops that keeps circulating, and a single 1-bit adder, plus four carry flip-flops, does the additions as the bits go past.

**Where the key lives.** HMAC starts both of its hashes with one block made only from the key. The two hash states after those blocks ("inner" and "outer") are the key in pre-mixed form, and they are what the chip stores, in two more 192-bit loops that turn in step with the working loop. A login code then needs only public data: the time counter for the inner hash, and the inner result for the outer hash. For each, the chip copies a stored state into the working loop, runs the 80 rounds, and does the final addition itself, reading the stored state straight from its loop. No command ever sends a stored state back out.

**Enrollment.** The computer sends the sky photo through the chip's hash (mixed with the computer's own randomness) to make the secret, shows it once as a link for your authenticator app, loads the pre-mixed states into the chip, and forgets it.

**What the computer still does.** It expands each public block into the 80 message words SHA-1 needs and streams them in. None of that work touches the key.

Serial protocol (115,200 baud, 8N1, 10 MHz clock):

| Byte | Meaning |
|------|---------|
| `?`  | Replies `K` |
| `T`  | Built-in self-test: hashes a known block from an on-chip table and replies `P` or `F` |
| `L`  | Load the key: 20 bytes inner state + 20 bytes outer state; replies `L` |
| `I`  | Keyed hash with the inner state: 320 message-word bytes in, finished 20-byte hash out |
| `O`  | The same with the outer state |
| `Z`  | Wipe the key; replies `Z` |
| `B`  | Plain hash, no key: 20 start-value bytes and 320 message-word bytes; replies with 20 bytes |

The 7-segment display shows H while hashing, P after a pass, F after a fail, and a dash when idle.

## How to test

Run `make -C test` (cocotb + Icarus) to check the chip against FIPS SHA-1, RFC 2202 HMAC and RFC 6238 TOTP vectors, with the key both on the computer and held on the chip, plus a wipe test and random blocks. On hardware, send `?` and expect `K`, then `T` and expect `P`. From a computer: `python host/skykey.py --port <port> selftest`, then `enroll --image sky.jpg`, then `code`.

## Honest limits

This is a design demonstration, not a certified security key. The chip has no permanent memory, so the key is lost when power goes off (enroll again), and it has no clock of its own (the computer supplies the time). Like any TOTP token, the secret is shared once with the service at enrollment. The chip accepts message words from the computer as given, so it relies on the strength of SHA-1's rounds rather than checking them.

## External hardware

A USB-serial adapter (or an RP2040/ESP32) wired to RX (ui[0]) and TX (uio[0]). Optional: a 7-segment display on uo[0..6].
