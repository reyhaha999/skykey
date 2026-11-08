/*
 * Copyright (c) 2026 Sehrey Kita
 * SPDX-License-Identifier: Apache-2.0
 *
 * Bit-serial SHA-1 round engine.
 *
 * SHA-1 mixes a 64-byte block through 80 "rounds".  Each round needs five
 * 32-bit working variables (a,b,c,d,e) and one 32-bit message word.  This
 * engine does all 80 rounds, one bit per clock:
 *
 *   v   192 bits  working ring.  Holds the five variables as five 32-bit
 *                 windows (plus one spare).  It never stops moving: when no
 *                 round is running it simply turns around on itself.
 *   wr   32 bits  message ring.  Holds the current message word.
 *
 * The message words come from the computer (it expands the block into 80
 * words and streams them in), and the computer adds the result back into the
 * hash state at the end.  That keeps the chip down to about 220 bits of state.
 *
 * Timing: `j` counts bits inside a word, `q` counts words inside the
 * six-word turn of the ring.  Round R starts when q == R mod 6, because
 * after each round the ring has moved on by exactly one word.
 *
 * Where the taps come from (see docs/info.md): at the start of a round the
 * ring holds a_R in cells 160..191, a_(R-1) in 128..159, a_(R-2) in 96..127,
 * a_(R-3) in 64..95 and a_(R-4) in 32..63, where a_R is the "new a" made by
 * round R-1.  b = a_(R-1), c = rotl30(a_(R-2)), d = rotl30(a_(R-3)),
 * e = rotl30(a_(R-4)).  A rotation is just a different tap position.
 */

`default_nettype none

module sha1_core (
    input  wire       clk,
    input  wire       rst,
    input  wire       arm,      // pulse: a new block starts; round 0 runs at q == 0
    input  wire       wz,       // self-test: every message word is zero
    input  wire       v_force,  // overwrite the bit entering the working ring
    input  wire       v_bit,
    input  wire       w_force,  // overwrite the bit entering the message ring
    input  wire       w_bit,
    input  wire       w_set,    // pulse: the message ring holds a complete word
    output reg  [4:0] j,
    output reg  [2:0] q,
    output wire       vout,     // bit leaving the working ring (for reading results)
    output reg        wvalid,   // a word is waiting for its round
    output reg  [6:0] rnd,      // rounds finished so far
    output reg        done,     // pulse after round 79
    output wire       busy
);

  reg [191:0] v;
  reg [31:0] wr;
  reg [3:0] cr;  // carries of the four serial adders
  reg run, armed;
  reg [2:0] rq;  // slot (q value) of the next round

  wire j0 = (j == 5'd0);
  wire jend = (j == 5'd31);
  wire jhi = (j[4:1] == 4'b1111);  // j >= 30
  wire jlt5 = (j < 5'd5);
  wire [2:0] qn = (q == 3'd5) ? 3'd0 : q + 3'd1;
  wire wv = wvalid | wz;

  assign vout = v[0];
  assign busy = armed;

  // ---- taps into the working ring ----
  wire tap_a = v[160];
  wire tap_a5 = jlt5 ? v[187] : v[155];  // rotl5(a)
  wire tap_b = v[128];
  wire tap_c = jhi ? v[66] : v[98];  // rotl30 of an older a
  wire tap_d = jhi ? v[34] : v[66];
  wire tap_e = jhi ? v[2] : v[34];

  // ---- round function ----
  wire [1:0] ph = (rnd < 7'd20) ? 2'd0 : (rnd < 7'd40) ? 2'd1 : (rnd < 7'd60) ? 2'd2 : 2'd3;

  reg f;
  always @* begin
    case (ph)
      2'd0: f = (tap_b & tap_c) | (~tap_b & tap_d);
      2'd2: f = (tap_b & tap_c) | (tap_b & tap_d) | (tap_c & tap_d);
      default: f = tap_b ^ tap_c ^ tap_d;
    endcase
  end

  reg [31:0] kword;
  always @* begin
    case (ph)
      2'd0: kword = 32'h5A827999;
      2'd1: kword = 32'h6ED9EBA1;
      2'd2: kword = 32'h8F1BBCDC;
      default: kword = 32'hCA62C1D6;
    endcase
  end
  wire kbit = kword[j];
  wire w_cur = wz ? 1'b0 : wr[0];

  // temp = rotl5(a) + f + e + K + W, one bit per clock with 4 serial adders
  wire ci1 = j0 ? 1'b0 : cr[0];
  wire ci2 = j0 ? 1'b0 : cr[1];
  wire ci3 = j0 ? 1'b0 : cr[2];
  wire ci4 = j0 ? 1'b0 : cr[3];
  wire s1 = tap_a5 ^ f ^ ci1;
  wire c1 = (tap_a5 & f) | (tap_a5 & ci1) | (f & ci1);
  wire s2 = s1 ^ tap_e ^ ci2;
  wire c2 = (s1 & tap_e) | (s1 & ci2) | (tap_e & ci2);
  wire s3 = s2 ^ kbit ^ ci3;
  wire c3 = (s2 & kbit) | (s2 & ci3) | (kbit & ci3);
  wire s4 = s3 ^ w_cur ^ ci4;
  wire c4 = (s3 & w_cur) | (s3 & ci4) | (w_cur & ci4);

  // keep tap_a referenced for documentation of the layout (a itself is not
  // needed by the round: it only reaches the sum as rotl5(a) and as b)
  wire _unused = &{tap_a, 1'b0};

  wire vin = v_force ? v_bit : run ? s4 : v[0];
  wire win = w_force ? w_bit : wr[0];

  always @(posedge clk) begin
    // free-running rings: no reset, no enable, smallest possible flops
    v  <= {vin, v[191:1]};
    wr <= {win, wr[31:1]};
    cr <= {c4, c3, c2, c1};
  end

  always @(posedge clk) begin
    if (rst) begin
      j      <= 5'd0;
      q      <= 3'd0;
      rnd    <= 7'd0;
      rq     <= 3'd0;
      run    <= 1'b0;
      armed  <= 1'b0;
      wvalid <= 1'b0;
      done   <= 1'b0;
    end else begin
      j    <= j + 5'd1;
      done <= 1'b0;
      if (jend) q <= qn;
      if (arm) begin
        armed  <= 1'b1;
        rnd    <= 7'd0;
        rq     <= 3'd0;
        wvalid <= 1'b0;
        run    <= 1'b0;
      end else begin
        if (w_set) wvalid <= 1'b1;
        // decide one clock early so `run` is high for exactly j = 0..31
        if (armed & ~run & wv & jend & (qn == rq)) run <= 1'b1;
        if (run & jend) begin
          run    <= 1'b0;
          rnd    <= rnd + 7'd1;
          rq     <= (rq == 3'd5) ? 3'd0 : rq + 3'd1;
          wvalid <= 1'b0;
          if (rnd == 7'd79) begin
            armed <= 1'b0;
            done  <= 1'b1;
          end
        end
      end
    end
  end

endmodule
