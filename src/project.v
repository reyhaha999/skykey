/*
 * Copyright (c) 2026 Sehrey Kita
 * SPDX-License-Identifier: Apache-2.0
 *
 * SkyKey: a tiny SHA-1 round engine on a chip, driven over a serial link.
 * A computer builds SHA-1, HMAC and one-time login codes (TOTP) out of it.
 *
 * Serial link: 115,200 baud, 8N1, 10 MHz clock.
 *
 *   '?'   chip replies 'K'
 *   'T'   self-test: the chip runs a known block through itself and checks the
 *         known answer.  Replies 'P' (pass) or 'F' (fail).
 *   'B'   run one block.  The computer then sends
 *            20 bytes   starting values  a0, a-1, a-2, a-3, a-4  (big endian words)
 *           320 bytes   the 80 message words W0..W79            (big endian words)
 *         and the chip replies with 20 bytes: the five values a80..a76.
 *         (host/skykey.py does the message expansion and the final addition.)
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
  wire [4:0] j;
  wire [2:0] q;
  wire       vout, wvalid, core_done, core_busy;
  wire [6:0] rnd;
  reg        arm, w_set, bist;
  wire       v_force, v_bit, w_force, w_bit;

  sha1_core u_core (
      .clk(clk),
      .rst(rst),
      .arm(arm),
      .wz(bist),
      .v_force(v_force),
      .v_bit(v_bit),
      .w_force(w_force),
      .w_bit(w_bit),
      .w_set(w_set),
      .j(j),
      .q(q),
      .vout(vout),
      .wvalid(wvalid),
      .rnd(rnd),
      .done(core_done),
      .busy(core_busy)
  );

  // ----------------------------------------------------------- self-test data
  // Starting values for the standard SHA-1 initial state, and the five values
  // the rounds must produce when every message word is zero.  Both were
  // computed with the software model in host/skykey.py.
  localparam [159:0] PRE = 160'h67452301efcdab8962eb73fa40c951d80f4b87c3;
  localparam [159:0] EXP = 160'h2b6ee1e4668ae1644d7fc143bb4babca1891628d;

  reg [4:0] n;  // byte counter
  wire [7:0] pre_byte = PRE[(5'd19 - n) * 8+:8];
  wire [7:0] exp_byte = EXP[(5'd19 - n) * 8+:8];

  // ----------------------------------------------------------------- control
  localparam [2:0] C_IDLE = 3'd0, C_LD = 3'd1, C_WR = 3'd2, C_TXD = 3'd3;

  reg [2:0] cs;
  reg       pending;  // a received byte is waiting for its slot
  reg       ins;  // inserting a byte (8 clocks)
  reg       capping;  // capturing a result byte (8 clocks)
  reg       mism;
  reg [1:0] res;  // 0 none, 1 pass, 2 fail

  wire [2:0] bi = j[2:0];

  // where do the bytes of the five starting values go?  word m (0..4) sits in
  // turn-slot q = 5 - m, and the byte inside the word picks j[4:3] = 3 - b
  wire [2:0] mword = n[4:2];
  wire [2:0] q_ins = 3'd5 - mword;
  // where do the five result words appear?  a80 in q=1, a79 in q=0, then 5,4,3
  reg [2:0] q_rd;
  always @* begin
    case (n[4:2])
      3'd0: q_rd = 3'd1;
      3'd1: q_rd = 3'd0;
      3'd2: q_rd = 3'd5;
      3'd3: q_rd = 3'd4;
      default: q_rd = 3'd3;
    endcase
  end

  wire have = (cs == C_LD) ? (bist | pending) : (pending & ~wvalid);
  wire slot_ld = (q == q_ins) & (j[4:3] == ~n[1:0]);
  wire slot_wr = (j[4:3] == ~n[1:0]);
  wire slot_ok = (cs == C_LD) ? slot_ld : slot_wr;
  wire in_rx = (cs == C_LD) | (cs == C_WR);
  wire ins_start = in_rx & have & ~ins & slot_ok & (bi == 3'd0);
  wire ins_act = in_rx & (ins | ins_start);
  wire [7:0] ins_byte = (cs == C_LD & bist) ? pre_byte : cap;  // cap holds the received byte
  wire ins_bit = ins_byte[bi];
  wire ins_last = ins_act & (bi == 3'd7);

  assign v_force = (cs == C_LD) & ins_act;
  assign v_bit = ins_bit;
  assign w_force = (cs == C_WR) & ins_act;
  assign w_bit = ins_bit;

  wire cap_start = (cs == C_TXD) & ~capping & ~send_pending & (bist | ~tx_busy) &
                   (q == q_rd) & (j[4:3] == ~n[1:0]) & (bi == 3'd0);
  wire cap_act = capping | cap_start;
  wire [7:0] cap_next = {vout, cap[7:1]};
  wire cap_last = cap_act & (bi == 3'd7);
  wire byte_bad = (cap_next != exp_byte);

  always @(posedge clk) begin
    if (rst) begin
      cs           <= C_IDLE;
      n            <= 5'd0;
      pending      <= 1'b0;
      ins          <= 1'b0;
      capping      <= 1'b0;
      mism         <= 1'b0;
      res          <= 2'd0;
      arm          <= 1'b0;
      w_set        <= 1'b0;
      bist         <= 1'b0;
      send_pending <= 1'b0;
      cap          <= 8'd0;
    end else begin
      arm   <= 1'b0;
      w_set <= 1'b0;
      if (tx_go) send_pending <= 1'b0;
      if (rx_valid) begin
        pending <= 1'b1;
        // keep the byte: the serial port starts overwriting it when the next one arrives
        if (in_rx) cap <= rx_data;
      end

      if (ins_start) ins <= 1'b1;
      if (ins_last) ins <= 1'b0;
      if (cap_start) capping <= 1'b1;
      if (cap_act) cap <= cap_next;
      if (cap_last) capping <= 1'b0;

      case (cs)
        C_IDLE: begin
          if (pending & ~rx_valid) begin
            pending <= 1'b0;
            n       <= 5'd0;
            case (rx_data)
              "?": begin
                cap          <= 8'h4B;
                send_pending <= 1'b1;
              end
              "B": begin
                cs   <= C_LD;
                bist <= 1'b0;
              end
              "T": begin
                cs   <= C_LD;
                bist <= 1'b1;
                mism <= 1'b0;
              end
              default: ;
            endcase
          end
        end
        C_LD: begin  // five starting values into the working ring
          if (ins_last) begin
            if (!bist) pending <= 1'b0;
            n <= n + 5'd1;
            if (n == 5'd19) begin
              arm <= 1'b1;
              n   <= 5'd0;
              cs  <= C_WR;
            end
          end
        end
        C_WR: begin  // 80 message words (computer sends them, or self-test uses zeros)
          if (ins_last) begin
            pending <= 1'b0;
            n       <= n + 5'd1;
            if (n[1:0] == 2'd3) w_set <= 1'b1;
          end
          if (core_done) begin
            cs <= C_TXD;
            n  <= 5'd0;
          end
        end
        C_TXD: begin  // read the five result words back out of the ring
          if (cap_last) begin
            if (bist) begin
              mism <= mism | byte_bad;
              n    <= n + 5'd1;
              if (n == 5'd19) begin
                cs           <= C_IDLE;
                bist         <= 1'b0;
                res          <= (mism | byte_bad) ? 2'd2 : 2'd1;
                cap          <= (mism | byte_bad) ? 8'h46 : 8'h50;
                send_pending <= 1'b1;
              end
            end else begin
              send_pending <= 1'b1;
            end
          end
          if (!bist && tx_go) begin
            n <= n + 5'd1;
            if (n == 5'd19) cs <= C_IDLE;
          end
        end
        default: cs <= C_IDLE;
      endcase
    end
  end

  // ------------------------------------------------------------- 7-seg + pins
  wire busy_any = (cs != C_IDLE);
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

  wire _unused = &{ena, ui_in[7:1], uio_in, core_busy, rnd, 1'b0};

endmodule
