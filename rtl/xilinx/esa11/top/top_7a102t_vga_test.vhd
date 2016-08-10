-- (c) EMARD
-- LICENSE=BSD

library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.STD_LOGIC_ARITH.ALL;
use IEEE.STD_LOGIC_UNSIGNED.ALL;
use ieee.math_real.all; -- to calculate log2 bit size

library unisim;
use unisim.vcomponents.all;

entity esa11_xram_axiram_ddr3 is
  generic (
	-- Main clock: 25/100 MHz
	C_clk_freq: integer := 100;

	C_vendor_specific_startup: boolean := false; -- false: disabled (xilinx startup doesn't work reliable on this board)

	-- SoC configuration options
	C_bram_size: integer := 16;

        -- axi ram
	C_axiram: boolean := false;

        -- warning: 2K, 4K, 8K, 16K, 32K cache produces timing critical warnings at 100MHz cpu clock
        C_icache_size: integer := 4; -- 0, 2, 4, 8, 16, 32 KBytes
        C_dcache_size: integer := 4; -- 0, 2, 4, 8, 16, 32 KBytes
        C_cached_addr_bits: integer := 29; -- lower address bits than C_cached_addr_bits are cached: 2^29 -> 512MB to be cached

        C3_NUM_DQ_PINS        : integer := 16;
        C3_MEM_ADDR_WIDTH     : integer := 14;
        C3_MEM_BANKADDR_WIDTH : integer := 3;

        C_vector: boolean := false; -- vector processor unit
        C_vector_axi: boolean := true; -- true: use AXI I/O, false use f32c RAM port I/O
        C_vector_registers: integer := 8; -- number of internal vector registers min 2, each takes 8K
        C_vector_vaddr_bits: integer := 11;
        C_vector_vdata_bits: integer := 32;
        C_vector_float_addsub: boolean := true; -- false will not have float addsub (+,-)
        C_vector_float_multiply: boolean := true; -- false will not have float multiply (*)
        C_vector_float_divide: boolean := true; -- false will not have float divide (/) will save much LUTs and DSPs

        C_video_mode: integer := 0; -- 0:640x480, 1:800x600, 2:1024x768
        C_dvid_ddr: boolean := true; -- false: clk_pixel_shift = 250MHz, true: clk_pixel_shift = 125MHz (DDR output driver)

        C_vgahdmi: boolean := true;
          C_vgahdmi_axi: boolean := true; -- connect vgahdmi to video_axi_in/out instead to f32c bus arbiter
          C_vgahdmi_cache_size: integer := 8; -- KB video cache (only on f32c bus) (0: disable, 2,4,8,16,32:enable)
          C_vgahdmi_fifo_timeout: integer := 0;
          C_vgahdmi_fifo_burst_max: integer := 64;
          -- output data width 8bpp
          C_vgahdmi_fifo_data_width: integer := 32; -- should be equal to bitmap depth
          -- bitmap width of FIFO address space length = 2^width * 4 byte
          C_vgahdmi_fifo_addr_width: integer := 11;

    C_vgatext: boolean := false;    -- Xark's feature-rich bitmap+textmode VGA
      C_vgatext_label: string := "f32c: ESA11-7a102t MIPS compatible soft-core 100MHz 256MB DDR3"; -- default banner as initial content of screen BRAM, NOP for RAM
      C_vgatext_mode: integer := 0;   -- 640x480
      C_vgatext_bits: integer := 4;   -- 64 possible colors
      C_vgatext_bram_mem: integer := 0;   -- KB (0: bram disabled -> use RAM)
      C_vgatext_bram_base: std_logic_vector(31 downto 28) := x"4"; -- textmode bram at 0x40000000
      C_vgatext_external_mem: integer := 32768; -- 32MB external SRAM/SDRAM
      C_vgatext_reset: boolean := true; -- reset registers to default with async reset
      C_vgatext_palette: boolean := true; -- no color palette
      C_vgatext_text: boolean := true; -- enable optional text generation
        C_vgatext_font_bram8: boolean := true; -- font in separate bram8 file (for Lattice XP2 BRAM or non power-of-two BRAM sizes)
        C_vgatext_char_height: integer := 16; -- character cell height
        C_vgatext_font_height: integer := 16; -- font height
        C_vgatext_font_depth: integer := 8; -- font char depth, 7=128 characters or 8=256 characters
        C_vgatext_font_linedouble: boolean := false;   -- double font height by doubling each line (e.g., so 8x8 font fills 8x16 cell)
        C_vgatext_font_widthdouble: boolean := false;   -- double font width by doubling each pixel (e.g., so 8 wide font is 16 wide cell)
        C_vgatext_monochrome: boolean := false;    -- true for 2-color text for whole screen, else additional color attribute byte per character
        C_vgatext_finescroll: boolean := true;   -- true for pixel level character scrolling and line length modulo
        C_vgatext_cursor: boolean := true;    -- true for optional text cursor
        C_vgatext_cursor_blink: boolean := true;    -- true for optional blinking text cursor
        C_vgatext_bus_read: boolean := false; -- true to allow reading vgatext BRAM from CPU bus (may affect fmax). false is write only
        C_vgatext_reg_read: boolean := true; -- true to allow reading vgatext BRAM from CPU bus (may affect fmax). false is write only
        C_vgatext_text_fifo: boolean := true;  -- enable text memory FIFO
          C_vgatext_text_fifo_postpone_step: integer := 0;
          C_vgatext_text_fifo_step: integer := (82*2)/4; -- step for the FIFO refill and rewind
          C_vgatext_text_fifo_width: integer := 6; -- width of FIFO address space (default=4) length = 2^width * 4 bytes
      C_vgatext_bitmap: boolean := true; -- true for optional bitmap generation
        C_vgatext_bitmap_depth: integer := 8; -- 8-bpp 256-color bitmap
        C_vgatext_bitmap_fifo: boolean := true; -- enable bitmap FIFO
          C_vgatext_bitmap_fifo_timeout: integer := 48; -- abort compositing 48 pixels before end of line
          -- 8 bpp compositing
          -- step=horizontal width in pixels
          C_vgatext_bitmap_fifo_step: integer := 640;
          -- height=vertical height in pixels
          C_vgatext_bitmap_fifo_height: integer := 480;
          -- output data width 8bpp
          C_vgatext_bitmap_fifo_data_width: integer := 8; -- should be equal to bitmap depth
          -- bitmap width of FIFO address space length = 2^width * 4 byte
          C_vgatext_bitmap_fifo_addr_width: integer := 11;

    C_sio: integer := 1;   -- 1 UART channel
    C_spi: integer := 2;   -- 2 SPI channels (ch0 not connected, ch1 SD card)
    C_timer: boolean := true; -- false: no timer
    C_ps2: boolean := false; -- no PS/2 keyboard
    C_gpio: integer := 32; -- 0: disabled, 32:32 GPIO bits
    C_simple_io: boolean := true -- includes 31 simple inputs and 32 simple outputs
  );
  port (
	i_100MHz_P, i_100MHz_N: in std_logic;
	UART1_TXD: out std_logic;
	UART1_RXD: in std_logic;
	FPGA_SD_SCLK, FPGA_SD_CMD, FPGA_SD_D3: out std_logic;
	FPGA_SD_D0: in std_logic;
	-- two onboard green LEDs next to yellow and red
        --FPGA_LED2, FPGA_LED3: out std_logic;
        -- DDR3 ------------------------------------------------------------------
        DDR_DQ                  : inout  std_logic_vector(C3_NUM_DQ_PINS-1 downto 0);       -- mcb3_dram_dq
        DDR_A                   : out    std_logic_vector(C3_MEM_ADDR_WIDTH-1 downto 0);    -- mcb3_dram_a
        DDR_BA                  : out    std_logic_vector(C3_MEM_BANKADDR_WIDTH-1 downto 0);-- mcb3_dram_ba
        DDR_RAS_N               : out    std_logic;                                         -- mcb3_dram_ras_n
        DDR_CAS_N               : out    std_logic;                                         -- mcb3_dram_cas_n
        DDR_WE_N                : out    std_logic;                                         -- mcb3_dram_we_n
        DDR_ODT                 : out    std_logic;                                         -- mcb3_dram_odt
        DDR_CKE                 : out    std_logic;                                         -- mcb3_dram_cke
        DDR_LDM                 : out    std_logic;                                         -- mcb3_dram_dm
        DDR_DQS_P               : inout  std_logic_vector(1 downto 0);                      -- mcb3_dram_udqs
        DDR_DQS_N               : inout  std_logic_vector(1 downto 0);                      -- mcb3_dram_udqs_n
        DDR_UDM                 : out    std_logic;                                         -- mcb3_dram_udm
        DDR_CK_P                : out    std_logic;                                         -- mcb3_dram_ck
        DDR_CK_N                : out    std_logic;                                         -- mcb3_dram_ck_n
        DDR_RESET_N             : out    std_logic;
      
	M_EXPMOD0, M_EXPMOD1, M_EXPMOD2, M_EXPMOD3: inout std_logic_vector(7 downto 0); -- EXPMODs
	M_7SEG_A, M_7SEG_B, M_7SEG_C, M_7SEG_D, M_7SEG_E, M_7SEG_F, M_7SEG_G, M_7SEG_DP: out std_logic;
	M_7SEG_DIGIT: out std_logic_vector(3 downto 0);
--	seg: out std_logic_vector(7 downto 0); -- 7-segment display
--	an: out std_logic_vector(3 downto 0); -- 7-segment display
	M_LED: out std_logic_vector(7 downto 0);
	-- PS/2 keyboard
	PS2_A_DATA, PS2_A_CLK, PS2_B_DATA, PS2_B_CLK: inout std_logic;
        -- HDMI
	VID_D_P, VID_D_N: out std_logic_vector(2 downto 0);
	VID_CLK_P, VID_CLK_N: out std_logic;
        -- VGA
        VGA_RED, VGA_GREEN, VGA_BLUE: out std_logic_vector(7 downto 0);
        VGA_SYNC_N, VGA_BLANK_N, VGA_CLOCK_P: out std_logic;
        VGA_HSYNC, VGA_VSYNC: out std_logic;
	M_BTN: in std_logic_vector(4 downto 0);
	M_HEX: in std_logic_vector(3 downto 0)
  );
end esa11_xram_axiram_ddr3;

architecture Behavioral of esa11_xram_axiram_ddr3 is
    -- useful for conversion from KB to number of address bits
    function ceil_log2(x: integer)
      return integer is
    begin
      return integer(ceil((log2(real(x)-1.0E-6))-1.0E-6)); -- 256 -> 8, 257 -> 9
    end ceil_log2;
    signal clk, sio_break: std_logic;
    signal clk_25MHz, clk_100MHz, clk_200MHz, clk_250MHz: std_logic;
    signal clk_40MHz: std_logic;
    signal clk_125MHz: std_logic := '0';
    signal clk_pixel: std_logic;
    signal clk_pixel_shift: std_logic;
    signal clk_locked: std_logic := '0';
    signal cfgmclk: std_logic;

    component clk_d100_100_200_250_25MHz is
    Port (
      clk_100mhz_in_p : in STD_LOGIC;
      clk_100mhz_in_n : in STD_LOGIC;
      clk_100mhz : out STD_LOGIC;
      clk_200mhz : out STD_LOGIC;
      clk_250mhz : out STD_LOGIC;
      clk_25mhz : out STD_LOGIC;
      reset : in STD_LOGIC;
      locked : out STD_LOGIC
    );
    end component clk_d100_100_200_250_25MHz;

    component clk_d100_100_200_125_25MHz is
    Port (
      clk_100mhz_in_p : in STD_LOGIC;
      clk_100mhz_in_n : in STD_LOGIC;
      clk_100mhz : out STD_LOGIC;
      clk_200mhz : out STD_LOGIC;
      clk_125mhz : out STD_LOGIC;
      clk_25mhz : out STD_LOGIC;
      reset : in STD_LOGIC;
      locked : out STD_LOGIC
    );
    end component clk_d100_100_200_125_25MHz;

    component clk_d100_100_200_40MHz is
    Port (
      clk_100mhz_in_p : in STD_LOGIC;
      clk_100mhz_in_n : in STD_LOGIC;
      clk_100mhz : out STD_LOGIC;
      clk_200mhz : out STD_LOGIC;
      clk_40mhz : out STD_LOGIC;
      reset : in STD_LOGIC;
      locked : out STD_LOGIC
    );
    end component clk_d100_100_200_40MHz;

    signal calib_done           : std_logic := '0';

    signal ram_en             : std_logic;
    signal ram_byte_we        : std_logic_vector(3 downto 0);
    signal ram_address        : std_logic_vector(29 downto 2);
    signal ram_data_write     : std_logic_vector(31 downto 0);
    signal ram_data_read      : std_logic_vector(31 downto 0);
    signal ram_read_busy      : std_logic := '0';
    signal ram_ready          : std_logic := '1';
    signal ram_cache_debug    : std_logic_vector(7 downto 0);
    signal ram_cache_hitcnt   : std_logic_vector(31 downto 0);
    signal ram_cache_readcnt  : std_logic_vector(31 downto 0);

    signal vga_clk: std_logic;
    signal S_vga_red, S_vga_green, S_vga_blue: std_logic_vector(7 downto 0);
    signal S_vga_blank: std_logic;
    signal S_vga_vsync, S_vga_hsync: std_logic;
    signal S_vga_fetch_next, S_vga_line_repeat: std_logic;
    signal S_vga_active_enabled: std_logic;
    signal S_vga_addr: std_logic_vector(29 downto 2);
    signal S_vga_addr_strobe: std_logic;
    signal S_vga_suggest_cache: std_logic;
    signal S_vga_suggest_burst: std_logic_vector(15 downto 0);
    signal S_vga_data, S_vga_data_debug: std_logic_vector(31 downto 0);
    signal S_vga_read_ready: std_logic;
    signal S_vga_data_ready: std_logic;
    signal red_byte, green_byte, blue_byte: std_logic_vector(7 downto 0);
    signal vga_data_from_fifo: std_logic_vector(31 downto 0);
    signal vga_refresh: std_logic;
    signal vga_reg_dtack: std_logic; -- low active, ack from VGA reg access
    signal vga_ackback: std_logic := '0'; -- clear for ack_d, sys_clk domai
    signal vreg_en: std_logic := '1'; -- active high
    signal vreg_uds: std_logic := '0'; -- even byte-addr, data bits 8-15, low active
    signal vreg_lds: std_logic := '0'; -- odd byte-addr, data bits 0-7, low active
--   signal vreg_wbe : std_logic_vector(3 downto 0);
    signal vreg_we: std_logic := '1'; -- write enable, active low
    signal vreg_wait: std_logic := '0'; -- mem_pause from VGA reg acces
    signal vga_read : std_logic_vector(15 downto 0) := (others => '0');
    signal vga_window : std_logic;
    signal vblank_int : std_logic;
    
    signal video_axi_aclk: std_logic;


    -- to switch glue/plasma vga
    signal glue_vga_vsync, glue_vga_hsync: std_logic;
    signal glue_vga_red, glue_vga_green, glue_vga_blue: std_logic_vector(7 downto 0);

    signal gpio: std_logic_vector(127 downto 0);
    signal simple_in: std_logic_vector(31 downto 0);
    signal simple_out: std_logic_vector(31 downto 0);
    signal dvid_red, dvid_green, dvid_blue, dvid_clock: std_logic_vector(1 downto 0);
    signal tmds_rgb: std_logic_vector(2 downto 0);
    signal tmds_clk: std_logic;
    --signal vga_vsync_n, vga_hsync_n: std_logic;
    signal ps2_clk_in : std_logic;
    signal ps2_clk_out : std_logic;
    signal ps2_dat_in : std_logic;
    signal ps2_dat_out : std_logic;
    signal disp_7seg_segment: std_logic_vector(7 downto 0);
begin

    cpu100_hdmi_sdr: if C_clk_freq = 100 and not C_dvid_ddr generate
    clk100in_out100_200_250_25_sdr_640x480: clk_d100_100_200_250_25MHz
    port map(clk_100mhz_in_p => i_100MHz_P,
             clk_100mhz_in_n => i_100MHz_N,
             reset => '0',
             locked => clk_locked,
             clk_100mhz => clk_100MHz,
             clk_200mhz => clk_200MHz,
             clk_250mhz => clk_250MHz,
             clk_25mhz  => clk_25MHz
    );
    clk <= clk_100MHz;
    clk_pixel <= clk_25MHz;
    clk_pixel_shift <= clk_250MHz;
    video_axi_aclk <= clk_200MHz;
    end generate;

    cpu100_hdmi_ddr_640x480: if C_clk_freq = 100 and C_dvid_ddr and C_video_mode=0 generate
    clk100in_out100_200_125_25_ddr_640x480: clk_d100_100_200_125_25MHz
    port map(clk_100mhz_in_p => i_100MHz_P,
             clk_100mhz_in_n => i_100MHz_N,
             reset => '0',
             locked => clk_locked,
             clk_100mhz => clk_100MHz,
             clk_200mhz => clk_200MHz,
             clk_125mhz => clk_125MHz,
             clk_25mhz  => clk_25MHz
    );
    clk <= clk_100MHz;
    clk_pixel <= clk_25MHz;
    clk_pixel_shift <= clk_125MHz;
    video_axi_aclk <= clk_200MHz;
    end generate;

    cpu100M_ddr_800x600: if C_clk_freq = 100 and C_dvid_ddr and C_video_mode=1 generate
    clk_cpu100M_ddr_800x600: clk_d100_100_200_40MHz
    port map(clk_100mhz_in_p => i_100MHz_P,
             clk_100mhz_in_n => i_100MHz_N,
             reset => '0',
             locked => clk_locked,
             clk_100mhz => clk_100MHz,
             clk_200mhz => clk_200MHz,
             clk_40mhz  => clk_40MHz
    );
    clk <= clk_100MHz;
    clk_pixel <= clk_40MHz;
    clk_pixel_shift <= clk_200MHz;
    video_axi_aclk <= clk_200MHz;
    end generate;

    cpu25M_ddr_640x480: if C_clk_freq = 25 and C_dvid_ddr and C_video_mode=0 generate
    clk_cpu25M_ddr_640x480: clk_d100_100_200_125_25MHz
    port map(clk_100mhz_in_p => i_100MHz_P,
             clk_100mhz_in_n => i_100MHz_N,
             reset => '0',
             locked => clk_locked,
             clk_100mhz => clk_100MHz,
             clk_200mhz => clk_200MHz,
             clk_125mhz => clk_125MHz,
             clk_25mhz  => clk_25MHz
    );
    clk <= clk_25MHz;
    clk_pixel <= clk_25MHz;
    clk_pixel_shift <= clk_125MHz;
    video_axi_aclk <= clk_200MHz;
    end generate;

    cpu25M_ddr_800x600: if C_clk_freq = 25 and C_dvid_ddr and C_video_mode=1 generate
    clk_cpu25M_ddr_800x600: clk_d100_100_200_40MHz
    port map(clk_100mhz_in_p => i_100MHz_P,
             clk_100mhz_in_n => i_100MHz_N,
             reset => '0',
             locked => clk_locked,
             clk_100mhz => clk_100MHz,
             clk_200mhz => clk_200MHz,
             clk_40mhz  => clk_40MHz
    );
    clk <= clk_25MHz;
    clk_pixel <= clk_40MHz;
    clk_pixel_shift <= clk_200MHz;
    video_axi_aclk <= clk_200MHz;
    end generate;

    G_vendor_specific_startup: if C_vendor_specific_startup generate
    -- reset hard-block: Xilinx Artix-7 specific
    reset: startupe2
    generic map (
      prog_usr => "FALSE"
    )
    port map (
      cfgmclk => cfgmclk,
      clk => cfgmclk,
      gsr => '0',
      gts => '0',
      keyclearb => '0',
      pack => '1',
      usrcclko => clk,
      usrcclkts => '0',
      usrdoneo => '1',
      usrdonets => '0'
    );
    end generate;

    ps2_dat_in	<= PS2_A_DATA;
    PS2_A_DATA	<= '0' when ps2_dat_out='0' else 'Z';
    ps2_clk_in	<= PS2_A_CLK;
    PS2_A_CLK	<= '0' when ps2_clk_out='0' else 'Z';

    -- generic BRAM glue
    glue_vga_test: entity work.glue_vga_test
    generic map (
      C_clk_freq => C_clk_freq,
      --C_ps2 => C_ps2,
      C_dvid_ddr => C_dvid_ddr,
      --
      C_vgahdmi => C_vgahdmi,
      C_vgahdmi_mode => C_video_mode,
      C_vgahdmi_axi => C_vgahdmi_axi,
      C_vgahdmi_cache_size => C_vgahdmi_cache_size,
      C_vgahdmi_fifo_timeout => C_vgahdmi_fifo_timeout,
      C_vgahdmi_fifo_burst_max => C_vgahdmi_fifo_burst_max,
      --C_vgahdmi_fifo_width => C_vgahdmi_fifo_width,
      --C_vgahdmi_fifo_height => C_vgahdmi_fifo_height,
      C_vgahdmi_fifo_data_width => C_vgahdmi_fifo_data_width,
      C_vgahdmi_fifo_addr_width => C_vgahdmi_fifo_addr_width,

      -- vga advanced graphics text+compositing bitmap
      C_vgatext => C_vgatext,
      C_vgatext_label => C_vgatext_label,
      C_vgatext_mode => C_vgatext_mode,
      C_vgatext_bits => C_vgatext_bits,
      C_vgatext_bram_mem => C_vgatext_bram_mem,
      C_vgatext_bram_base => C_vgatext_bram_base,
      C_vgatext_external_mem => C_vgatext_external_mem,
      C_vgatext_reset => C_vgatext_reset,
      C_vgatext_palette => C_vgatext_palette,
      C_vgatext_text => C_vgatext_text,
      C_vgatext_font_bram8 => C_vgatext_font_bram8,
      C_vgatext_bus_read => C_vgatext_bus_read,
      C_vgatext_reg_read => C_vgatext_reg_read,
      C_vgatext_text_fifo => C_vgatext_text_fifo,
      C_vgatext_text_fifo_step => C_vgatext_text_fifo_step,
      C_vgatext_text_fifo_width => C_vgatext_text_fifo_width,
      C_vgatext_char_height => C_vgatext_char_height,
      C_vgatext_font_height => C_vgatext_font_height,
      C_vgatext_font_depth => C_vgatext_font_depth,
      C_vgatext_font_linedouble => C_vgatext_font_linedouble,
      C_vgatext_font_widthdouble => C_vgatext_font_widthdouble,
      C_vgatext_monochrome => C_vgatext_monochrome,
      C_vgatext_finescroll => C_vgatext_finescroll,
      C_vgatext_cursor => C_vgatext_cursor,
      C_vgatext_cursor_blink => C_vgatext_cursor_blink,
      C_vgatext_bitmap => C_vgatext_bitmap,
      C_vgatext_bitmap_depth => C_vgatext_bitmap_depth,
      C_vgatext_bitmap_fifo => C_vgatext_bitmap_fifo,
      C_vgatext_bitmap_fifo_timeout => C_vgatext_bitmap_fifo_timeout,
      C_vgatext_bitmap_fifo_step => C_vgatext_bitmap_fifo_step,
      C_vgatext_bitmap_fifo_height => C_vgatext_bitmap_fifo_height,
      C_vgatext_bitmap_fifo_data_width => C_vgatext_bitmap_fifo_data_width,
      C_vgatext_bitmap_fifo_addr_width => C_vgatext_bitmap_fifo_addr_width
    )
    port map (
        clk => clk,
	clk_pixel => clk_pixel,
	clk_pixel_shift => clk_pixel_shift,
        -- VGA/HDMI
	vga_vsync => glue_vga_vsync,
	vga_hsync => glue_vga_hsync,
	vga_r => glue_vga_red,
	vga_g => glue_vga_green,
	vga_b => glue_vga_blue,
        dvid_red   => dvid_red,
        dvid_green => dvid_green,
        dvid_blue  => dvid_blue,
        dvid_clock => dvid_clock
    );

    m_7seg_a  <= disp_7seg_segment(0);
    m_7seg_b  <= disp_7seg_segment(1);
    m_7seg_c  <= disp_7seg_segment(2);
    m_7seg_d  <= disp_7seg_segment(3);
    m_7seg_e  <= disp_7seg_segment(4);
    m_7seg_f  <= disp_7seg_segment(5);
    m_7seg_g  <= disp_7seg_segment(6);
    m_7seg_dp <= disp_7seg_segment(7);

    G_dvi_sdr: if not C_dvid_ddr generate
      tmds_rgb <= dvid_red(0) & dvid_green(0) & dvid_blue(0);
      tmds_clk <= dvid_clock(0);
    end generate;

    G_dvi_ddr: if C_dvid_ddr generate
    -- vendor specific modules to
    -- convert 2-bit pairs to DDR 1-bit
    G_vga_ddrout: entity work.ddr_dvid_out_se
    port map (
      clk       => clk_pixel_shift,
      clk_n     => '0', -- inverted shift clock not needed on xilinx
      in_red    => dvid_red,
      in_green  => dvid_green,
      in_blue   => dvid_blue,
      in_clock  => dvid_clock,
      out_red   => tmds_rgb(2),
      out_green => tmds_rgb(1),
      out_blue  => tmds_rgb(0),
      out_clock => tmds_clk
    );
    end generate;

    -- differential output buffering for HDMI clock and video
    hdmi_output: entity work.hdmi_out
    port map (
        tmds_in_clk => tmds_clk, -- clk_25MHz or tmds_clk
        tmds_out_clk_p => VID_CLK_P,
        tmds_out_clk_n => VID_CLK_N,
        tmds_in_rgb => tmds_rgb,
        tmds_out_rgb_p => VID_D_P,
        tmds_out_rgb_n => VID_D_N
    );

    vga_f32c: if C_vgahdmi or C_vgatext generate
    VGA_SYNC_N <= '1';
    VGA_BLANK_N <= '1';
    VGA_CLOCK_P <= clk_pixel;
    VGA_VSYNC <= glue_vga_vsync;
    VGA_HSYNC <= glue_vga_hsync;
    vga_red <= glue_vga_red;
    vga_green <= glue_vga_green;
    vga_blue <= glue_vga_blue;
    end generate;

end Behavioral;
