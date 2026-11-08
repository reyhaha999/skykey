/*
 * Copyright (c) 2026 Sehrey Kita
 * SPDX-License-Identifier: Apache-2.0
 *
 * SkyKey: a tiny SHA-1 hash engine on a chip, driven over a serial link.
 * A computer builds HMAC and one-time login codes (TOTP) out of it.
 *
 * Serial commands (38,400 baud, 8N1, 10 MHz clock):
 *   '?'            reply 'K'
 *   'S' + 20 bytes load the hash state H0..H4 (big endian)
 *   'I'            reset the hash state to the SHA-1 starting value, reply 'K'
 *   'B' + 64 bytes load a block, run SHA-1 on it, reply with the new 20-byte state
 *   'b' + 64 bytes same, but reply just 'K' (for blocks whose result is not needed)
 *   'Q'            reply with the current 20-byte state
 *   'T'            self-test (hashes "abc", checks the known answer), reply 'P' or 'F'
 */

`default_nettype none

module tt_um_reyhaha999_skykey (
    input  wire [7:0] ui_in,    // Dedicated inputs
    output wire [7:0] uo_out,   // Dedicated outputs
    input  wire [7:0] uio_in,   // IOs: Input path
    output wire [7:0] uio_out,  // IOs: Output path
    output wire [7:0] uio_oe,   // IOs: Enable path (active high: 0=input, 1=output)
    input  wire       ena,      // always 1 when the design is powered, so you can ignore it
    input  wire       clk,      // clock
    input  wire       rst_n     // reset_n - low to reset
);

  wire rst = ~rst_n;

  // ------------------------------------------------------------------ serial
  wire [7:0] rx_data;
  wire       rx_valid;
  wire       tx_line;
  wire       tx_busy;
  reg        send_pending;
  reg  [7:0] cap;  // byte being captured / sent
  wire       tx_go = send_pending & ~tx_busy;

  uart_rx u_rx (
      .clk(clk),
      .rst(rst),
      .rx(ui_in[0]),
      .data(rx_data),
      .valid(rx_valid)
  );
  uart_tx u_tx (
      .clk(clk),
      .rst(rst),
      .start(tx_go),
      .data(cap),
      .tx(tx_line),
      .busy(tx_busy)
  );

  // -------------------------------------------------------------------- core
  wire [8:0] cnt;
  wire [4:0] h_out;
  wire       core_busy, core_done;
  reg        start;
  wire       w_force, w_bit;
  wire [4:0] h_force, h_bits;

  sha1_core u_core (
      .clk(clk),
      .rst(rst),
      .start(start),
      .w_force(w_force),
      .w_bit(w_bit),
      .h_force(h_force),
      .h_bits(h_bits),
      .cnt(cnt),
      .h_out(h_out),
      .busy(core_busy),
      .done(core_done)
  );

  // ----------------------------------------------------------- self-test data
  localparam [31:0] W0 = 32'h61626380;  // "abc" + 0x80 padding bit
  localparam [31:0] W15 = 32'h00000018;  // message length: 24 bits
  localparam [159:0] IV = {32'hC3D2E1F0, 32'h10325476, 32'h98BADCFE, 32'hEFCDAB89, 32'h67452301};
  localparam [159:0] EXPECT = {
    32'h9CD0D89D, 32'h7850C26C, 32'hBA3E2571, 32'h4706816A, 32'hA9993E36
  };

  wire [3:0] cw = cnt[8:5];
  wire [4:0] cj = cnt[4:0];
  wire       bist_w = (cw == 4'd0) ? W0[cj] : (cw == 4'd15) ? W15[cj] : 1'b0;
  wire [4:0] iv_bits = {IV[128+cj], IV[96+cj], IV[64+cj], IV[32+cj], IV[cj]};
  wire [4:0] exp_bits = {EXPECT[128+cj], EXPECT[96+cj], EXPECT[64+cj], EXPECT[32+cj], EXPECT[cj]};

  // ----------------------------------------------------------------- control
  localparam [3:0] C_IDLE = 4'd0, C_SRX = 4'd1, C_BRX = 4'd2, C_RUN = 4'd3, C_TXD = 4'd4,
                   C_BLD = 4'd5, C_BRUN = 4'd6, C_BCMP = 4'd7, C_IV = 4'd8;

  reg [3:0] cs;
  reg       quiet;  // 'b' command: acknowledge with 'K' instead of the digest
  reg       ivm;  // loading the SHA-1 starting value
  reg [6:0] n;  // byte counter
  reg       pending;  // a received byte is waiting for its slot
  reg       ins;  // inserting the pending byte (8 clocks)
  reg       capping;  // capturing a digest byte (8 clocks)
  reg       bld;  // self-test load revolution
  reg       mism;
  reg [1:0] res;  // 0 none, 1 pass, 2 fail

  wire [2:0] bi = cnt[2:0];
  wire       in_rx = (cs == C_SRX) | (cs == C_BRX);
  wire       slot_w = (cnt[8:3] == (n[5:0] ^ 6'd3));
  wire       slot_h = (cnt[4:3] == ~n[1:0]);
  wire       slot_ok = (cs == C_BRX) ? slot_w : slot_h;
  wire       ins_start = in_rx & pending & ~ins & slot_ok & (bi == 3'd0);
  wire       ins_act = in_rx & (ins | ins_start);
  wire       ins_bit = rx_data[bi];
  wire       ins_last = ins_act & (bi == 3'd7);

  assign w_force = ((cs == C_BRX) & ins_act) | bld;
  assign w_bit = bld ? bist_w : ins_bit;
  assign h_force = ({5{bld & (cnt[8:5] == 4'd0)}}) | {5{ivm}} |
                   ({5{(cs == C_SRX) & ins_act}} & (5'b00001 << n[4:2]));
  assign h_bits = (bld | ivm) ? iv_bits : {5{ins_bit}};

  wire cap_start = (cs == C_TXD) & ~capping & ~send_pending & ~tx_busy &
                   (cnt[4:3] == ~n[1:0]) & (bi == 3'd0);
  wire cap_act = capping | cap_start;
  wire sel = h_out[n[4:2]];

  wire mm = |(h_out ^ exp_bits);

  always @(posedge clk) begin
    if (rst) begin
      cs           <= C_IDLE;
      n            <= 7'd0;
      pending      <= 1'b0;
      ins          <= 1'b0;
      capping      <= 1'b0;
      bld          <= 1'b0;
      quiet        <= 1'b0;
      ivm          <= 1'b0;
      mism         <= 1'b0;
      res          <= 2'd0;
      start        <= 1'b0;
      send_pending <= 1'b0;
      cap          <= 8'd0;
    end else begin
      start <= 1'b0;
      if (tx_go) send_pending <= 1'b0;
      if (rx_valid) pending <= 1'b1;

      if (ins_start) ins <= 1'b1;
      if (ins_last) ins <= 1'b0;
      if (cap_start) capping <= 1'b1;
      if (cap_act) cap <= {sel, cap[7:1]};
      if (cap_act & (bi == 3'd7)) begin
        capping      <= 1'b0;
        send_pending <= 1'b1;
      end

      case (cs)
        C_IDLE: begin
          if (pending & ~rx_valid) begin
            pending <= 1'b0;
            n       <= 7'd0;
            case (rx_data)
              "?": begin
                cap          <= 8'h4B;
                send_pending <= 1'b1;
              end
              "S": cs <= C_SRX;
              "B": begin
                cs    <= C_BRX;
                quiet <= 1'b0;
              end
              "b": begin
                cs    <= C_BRX;
                quiet <= 1'b1;
              end
              "I": cs <= C_IV;
              "Q": cs <= C_TXD;
              "T": begin
                cs  <= C_BLD;
                bld <= 1'b0;
              end
              default: ;
            endcase
          end
        end
        C_SRX: begin
          if (ins_last) begin
            pending <= 1'b0;
            n       <= n + 7'd1;
            if (n == 7'd19) begin
              cs           <= C_IDLE;
              cap          <= 8'h4B;
              send_pending <= 1'b1;
            end
          end
        end
        C_BRX: begin
          if (ins_last) begin
            pending <= 1'b0;
            n       <= n + 7'd1;
            if (n == 7'd63) begin
              cs    <= C_RUN;
              start <= 1'b1;
            end
          end
        end
        C_RUN: begin
          if (core_done) begin
            n <= 7'd0;
            if (quiet) begin
              cs           <= C_IDLE;
              cap          <= 8'h4B;
              send_pending <= 1'b1;
            end else begin
              cs <= C_TXD;
            end
          end
        end
        C_IV: begin  // one 32-clock word-time drops the starting value into H0..H4
          if (cnt[4:0] == 5'd31) begin
            if (ivm) begin
              ivm          <= 1'b0;
              cs           <= C_IDLE;
              cap          <= 8'h4B;
              send_pending <= 1'b1;
            end else begin
              ivm <= 1'b1;
            end
          end
        end
        C_TXD: begin
          if (tx_go) begin
            n <= n + 7'd1;
            if (n == 7'd19) cs <= C_IDLE;
          end
        end
        C_BLD: begin  // one full revolution drops "abc" into the message ring
          if (cnt == 9'd511) begin
            if (bld) begin
              bld   <= 1'b0;
              start <= 1'b1;
              cs    <= C_BRUN;
            end else begin
              bld <= 1'b1;
            end
          end
        end
        C_BRUN: begin
          if (core_done) begin
            cs   <= C_BCMP;
            mism <= 1'b0;
          end
        end
        C_BCMP: begin  // compare all five state words with the known answer
          mism <= mism | mm;
          if (cnt[4:0] == 5'd31) begin
            cs           <= C_IDLE;
            res          <= (mism | mm) ? 2'd2 : 2'd1;
            cap          <= (mism | mm) ? 8'h46 : 8'h50;
            send_pending <= 1'b1;
          end
        end
        default: cs <= C_IDLE;
      endcase
    end
  end

  // ------------------------------------------------------------- 7-seg + pins
  wire busy_any = (cs != C_IDLE) | core_busy;
  reg [6:0] seg;
  always @* begin
    if (busy_any) seg = 7'b1110110;  // H (hashing)
    else if (res == 2'd1) seg = 7'b1110011;  // P (pass)
    else if (res == 2'd2) seg = 7'b1110001;  // F (fail)
    else seg = 7'b1000000;  // -
  end

  assign uo_out  = {busy_any, seg};
  assign uio_out = {7'b0, tx_line};
  assign uio_oe  = 8'b00000001;

  wire _unused = &{ena, ui_in[7:1], uio_in, 1'b0};

endmodule
