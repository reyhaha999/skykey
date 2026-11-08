/*
 * Copyright (c) 2026 Sehrey Kita
 * SPDX-License-Identifier: Apache-2.0
 *
 * Serial port (UART), 8 data bits, no parity, 1 stop bit.
 * At the 10 MHz chip clock, 260 clock cycles per bit = 38,400 baud.
 */

`default_nettype none

module uart_rx #(
    parameter [8:0] CLKS_PER_BIT = 9'd260
) (
    input  wire       clk,
    input  wire       rst,
    input  wire       rx,
    output reg  [7:0] data,
    output reg        valid  // high for one clock when a byte arrives
);

  localparam [1:0] IDLE = 2'd0, START = 2'd1, DATA = 2'd2, STOP = 2'd3;
  localparam [8:0] LAST = CLKS_PER_BIT - 9'd1;
  localparam [8:0] HALF = CLKS_PER_BIT / 9'd2 - 9'd1;

  reg [1:0] rx_sync;
  reg [1:0] state;
  reg [8:0] cnt;
  reg [2:0] bit_idx;

  wire rx_s = rx_sync[1];

  always @(posedge clk) begin
    if (rst) begin
      rx_sync <= 2'b11;
      state   <= IDLE;
      cnt     <= 9'd0;
      bit_idx <= 3'd0;
      valid   <= 1'b0;
    end else begin
      rx_sync <= {rx_sync[0], rx};
      valid   <= 1'b0;
      case (state)
        IDLE: begin
          cnt <= 9'd0;
          if (!rx_s) state <= START;
        end
        START: begin  // wait to the middle of the start bit and make sure it is real
          if (cnt == HALF) begin
            cnt     <= 9'd0;
            bit_idx <= 3'd0;
            state   <= rx_s ? IDLE : DATA;
          end else begin
            cnt <= cnt + 9'd1;
          end
        end
        DATA: begin  // sample each bit in its middle, least significant bit first
          if (cnt == LAST) begin
            cnt  <= 9'd0;
            data <= {rx_s, data[7:1]};
            if (bit_idx == 3'd7) state <= STOP;
            bit_idx <= bit_idx + 3'd1;
          end else begin
            cnt <= cnt + 9'd1;
          end
        end
        STOP: begin
          if (cnt == LAST) begin
            cnt   <= 9'd0;
            valid <= rx_s;  // only accept the byte if the stop bit is high
            state <= IDLE;
          end else begin
            cnt <= cnt + 9'd1;
          end
        end
      endcase
    end
  end

endmodule


module uart_tx #(
    parameter [8:0] CLKS_PER_BIT = 9'd260
) (
    input  wire       clk,
    input  wire       rst,
    input  wire       start,  // pulse to send `data` (ignored while busy)
    input  wire [7:0] data,
    output wire       tx,
    output wire       busy
);

  localparam [8:0] LAST = CLKS_PER_BIT - 9'd1;

  reg [9:0] sh;
  reg [3:0] nb;
  reg [8:0] cnt;
  reg       act;

  assign busy = act;
  assign tx   = act ? sh[0] : 1'b1;

  always @(posedge clk) begin
    if (rst) begin
      act <= 1'b0;
      cnt <= 9'd0;
      nb  <= 4'd0;
    end else if (!act) begin
      if (start) begin
        sh  <= {1'b1, data, 1'b0};  // stop, data, start
        act <= 1'b1;
        cnt <= 9'd0;
        nb  <= 4'd0;
      end
    end else begin
      if (cnt == LAST) begin
        cnt <= 9'd0;
        sh  <= {1'b1, sh[9:1]};
        nb  <= nb + 4'd1;
        if (nb == 4'd9) act <= 1'b0;
      end else begin
        cnt <= cnt + 9'd1;
      end
    end
  end

endmodule
