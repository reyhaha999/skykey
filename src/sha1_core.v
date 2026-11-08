/*
 * Copyright (c) 2026 Sehrey Kita
 * SPDX-License-Identifier: Apache-2.0
 *
 * Bit-serial SHA-1 compression engine.
 *
 * Everything is a free-running shift register that moves one bit per clock,
 * so there is almost no multiplexing and the chip stays tiny:
 *
 *   r   513 bits   message ring  (16 words of the 64-byte block, +1 tail bit)
 *   v   190 bits   working ring  (the a,b,c,d,e variables of the algorithm)
 *   h0..h4  5 x 32 bits   state rings (the running hash value H0..H4)
 *
 * One SHA-1 round takes 32 clocks (one bit of every word per clock), so a
 * whole 64-byte block takes (5 + 80 + 1) * 32 = 2752 clocks.
 *
 * `cnt` is a free-running 9-bit counter.  Bit j of message word w always
 * passes the ring head when cnt == 32*w + j.  The outside world uses `cnt`
 * to drop bytes into the right slots (see project.v).
 */

`default_nettype none

module sha1_core (
    input  wire       clk,
    input  wire       rst,
    input  wire       start,    // pulse: compress the loaded block into H
    input  wire       w_force,  // overwrite the bit entering the message ring
    input  wire       w_bit,
    input  wire [4:0] h_force,  // overwrite the bit entering state ring i
    input  wire [4:0] h_bits,
    output reg  [8:0] cnt,      // free-running timebase
    output wire [4:0] h_out,    // bit j of H0..H4 at this clock
    output wire       busy,
    output wire       done      // high on the last clock of the final add
);

  localparam [1:0] S_IDLE = 2'd0, S_LOAD = 2'd1, S_RND = 2'd2, S_ADD = 2'd3;

  reg [1:0] st;
  reg [6:0] wc;  // word counter inside the current stage
  reg       pend;

  reg [512:0] r;
  reg [189:0] v;
  reg [31:0] h0, h1, h2, h3, h4;
  reg [3:0] cr;  // carries of the 4 serial adders in the round
  reg [4:0] ca;  // carries of the 5 serial adders in the final add

  wire [4:0] j = cnt[4:0];
  wire j0 = (j == 5'd0);
  wire jend = (j == 5'd31);
  wire jhi = (j[4:1] == 4'b1111);  // j >= 30
  wire jlt5 = (j < 5'd5);

  assign busy = pend | (st != S_IDLE);
  assign done = (st == S_ADD) & jend;
  assign h_out = {h4[0], h3[0], h2[0], h1[0], h0[0]};

  // ---- taps into the working ring (positions derived in docs/info.md) ----
  wire tap_a = v[158];
  wire tap_a5 = jlt5 ? v[185] : v[153];  // rotate-left-5 of a
  wire tap_b = v[126];
  wire tap_c = jhi ? v[64] : v[96];  // rotate-left-30 of the older a
  wire tap_d = jhi ? v[32] : v[64];
  wire tap_e = jhi ? v[0] : v[32];

  // ---- round function ----
  wire [1:0] ph = (wc < 7'd20) ? 2'd0 : (wc < 7'd40) ? 2'd1 : (wc < 7'd60) ? 2'd2 : 2'd3;

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

  // message schedule: W[t] = rotl1(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])
  wire first16 = (wc[6:4] == 3'b000);
  wire w_gen = j0 ? (r[448] ^ r[288] ^ r[96] ^ r[32]) : (r[416] ^ r[256] ^ r[64] ^ r[0]);
  wire in_rnd = (st == S_RND);
  wire w_cur = (in_rnd & ~first16) ? w_gen : r[1];
  wire w_in = w_force ? w_bit : w_cur;

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

  // what enters the working ring this clock
  reg vin;
  always @* begin
    case (st)
      S_LOAD: begin
        // pre-history so that the first round sees a,b,c,d,e = H0..H4
        case (wc[2:0])
          3'd0: vin = h4[30];  // rotl2(H4)
          3'd1: vin = h3[30];  // rotl2(H3)
          3'd2: vin = h2[30];  // rotl2(H2)
          3'd3: vin = h1[0];  // H1
          default: vin = h0[0];  // H0
        endcase
      end
      S_RND: vin = s4;
      default: vin = 1'b0;
    endcase
  end

  // final add: Hi = Hi + (a,b,c,d,e) after round 79
  wire in_add = (st == S_ADD);
  wire [4:0] vt = {tap_e, tap_d, tap_c, tap_b, tap_a};
  wire [4:0] ci = j0 ? 5'b0 : ca;
  wire [4:0] hz = h_out;
  wire [4:0] hsum = hz ^ vt ^ ci;
  wire [4:0] hcar = (hz & vt) | (hz & ci) | (vt & ci);

  wire [4:0] hnext = in_add ? hsum : hz;
  wire [4:0] hin = (h_force & h_bits) | (~h_force & hnext);

  always @(posedge clk) begin
    // free-running rings (no reset, no enable: smallest possible flops)
    r  <= {w_in, r[512:1]};
    v  <= {vin, v[189:1]};
    h0 <= {hin[0], h0[31:1]};
    h1 <= {hin[1], h1[31:1]};
    h2 <= {hin[2], h2[31:1]};
    h3 <= {hin[3], h3[31:1]};
    h4 <= {hin[4], h4[31:1]};
    cr <= {c4, c3, c2, c1};
    ca <= hcar;
  end

  always @(posedge clk) begin
    if (rst) begin
      cnt  <= 9'd0;
      st   <= S_IDLE;
      wc   <= 7'd0;
      pend <= 1'b0;
    end else begin
      cnt <= cnt + 9'd1;
      if (start) pend <= 1'b1;
      case (st)
        S_IDLE: begin
          // the first pre-history word must enter when cnt == 352 so that
          // round 0 starts exactly on cnt == 0 (message ring alignment)
          if (pend && cnt == 9'd351) begin
            st   <= S_LOAD;
            wc   <= 7'd0;
            pend <= 1'b0;
          end
        end
        S_LOAD: begin
          if (jend) begin
            if (wc == 7'd4) begin
              st <= S_RND;
              wc <= 7'd0;
            end else begin
              wc <= wc + 7'd1;
            end
          end
        end
        S_RND: begin
          if (jend) begin
            if (wc == 7'd79) st <= S_ADD;
            else wc <= wc + 7'd1;
          end
        end
        S_ADD: begin
          if (jend) st <= S_IDLE;
        end
      endcase
    end
  end

endmodule
