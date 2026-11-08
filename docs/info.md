<!---
This file is used to generate your project datasheet. Please fill in the information below and delete any unused sections.
-->

## How it works

SkyKey is a tiny hardware SHA-1 engine. A computer talks to it over a serial link, and builds HMAC and one-time login codes (TOTP) out of it.

(Full write-up is added once the design is verified.)

## How to test

Send `?` over the serial link at 38,400 baud. The chip answers `K`. Send `T` and it hashes "abc" and checks the known answer; the display shows P (pass) or F (fail).

## External hardware

A USB-serial adapter (or an RP2040/ESP32) wired to RX (ui[0]) and TX (uio[0]). Optional: a 7-segment display on uo[0..6].
