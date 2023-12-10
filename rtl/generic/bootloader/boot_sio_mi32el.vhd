library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.STD_LOGIC_ARITH.ALL;
use IEEE.STD_LOGIC_UNSIGNED.ALL;
use work.boot_block_pack.all;

package boot_sio_mi32el is

constant M_boot_sio_mi32el : boot_block_type := (
	x"00", x"00", x"00", x"00", x"25", x"48", x"00", x"00", 
	x"25", x"28", x"00", x"00", x"25", x"10", x"00", x"00", 
	x"ff", x"ff", x"0a", x"24", x"00", x"08", x"0b", x"3c", 
	x"01", x"00", x"0c", x"24", x"03", x"00", x"0d", x"24", 
	x"53", x"00", x"0e", x"24", x"6d", x"33", x"03", x"3c", 
	x"25", x"30", x"00", x"00", x"0d", x"0a", x"63", x"24", 
	x"3e", x"20", x"07", x"3c", x"04", x"fb", x"04", x"80", 
	x"02", x"00", x"84", x"30", x"fd", x"ff", x"80", x"14", 
	x"00", x"00", x"00", x"00", x"00", x"fb", x"03", x"a0", 
	x"03", x"1a", x"03", x"00", x"25", x"20", x"66", x"00", 
	x"24", x"00", x"80", x"10", x"00", x"00", x"00", x"00", 
	x"f6", x"ff", x"60", x"14", x"0d", x"00", x"0f", x"24", 
	x"ff", x"00", x"07", x"24", x"ff", x"ff", x"04", x"24", 
	x"02", x"00", x"08", x"24", x"03", x"ca", x"05", x"00", 
	x"24", x"00", x"81", x"04", x"00", x"00", x"00", x"00", 
	x"00", x"48", x"02", x"40", x"24", x"18", x"4b", x"00", 
	x"02", x"00", x"60", x"10", x"c3", x"c4", x"02", x"00", 
	x"ff", x"00", x"03", x"24", x"ff", x"00", x"46", x"30", 
	x"ff", x"00", x"18", x"33", x"2a", x"30", x"06", x"03", 
	x"18", x"00", x"c0", x"10", x"00", x"00", x"00", x"00", 
	x"0f", x"00", x"63", x"38", x"10", x"ff", x"03", x"a0", 
	x"04", x"fb", x"03", x"80", x"01", x"00", x"63", x"30", 
	x"ef", x"ff", x"60", x"10", x"00", x"00", x"00", x"00", 
	x"00", x"fb", x"03", x"80", x"1e", x"00", x"81", x"04", 
	x"f6", x"ff", x"66", x"24", x"0a", x"00", x"6e", x"10", 
	x"00", x"00", x"00", x"00", x"0f", x"00", x"6a", x"14", 
	x"00", x"00", x"00", x"00", x"8b", x"00", x"00", x"08", 
	x"00", x"00", x"00", x"00", x"e3", x"ff", x"00", x"10", 
	x"25", x"10", x"00", x"00", x"ff", x"ff", x"06", x"24", 
	x"d2", x"ff", x"00", x"10", x"32", x"6c", x"e3", x"24", 
	x"25", x"10", x"00", x"00", x"dd", x"ff", x"00", x"10", 
	x"25", x"20", x"00", x"00", x"e9", x"ff", x"00", x"10", 
	x"f0", x"00", x"63", x"38", x"e8", x"ff", x"00", x"10", 
	x"10", x"ff", x"19", x"a0", x"c5", x"ff", x"6f", x"10", 
	x"20", x"00", x"66", x"28", x"d5", x"ff", x"c0", x"14", 
	x"25", x"10", x"00", x"00", x"04", x"fb", x"02", x"80", 
	x"02", x"00", x"42", x"30", x"fd", x"ff", x"40", x"14", 
	x"00", x"00", x"00", x"00", x"00", x"fb", x"03", x"a0", 
	x"cf", x"ff", x"00", x"10", x"03", x"ca", x"05", x"00", 
	x"04", x"00", x"c6", x"2c", x"c8", x"ff", x"c0", x"14", 
	x"00", x"00", x"00", x"00", x"61", x"00", x"66", x"28", 
	x"16", x"00", x"c0", x"14", x"00", x"11", x"02", x"00", 
	x"e0", x"ff", x"63", x"24", x"c9", x"ff", x"63", x"24", 
	x"01", x"00", x"84", x"24", x"1b", x"00", x"8c", x"14", 
	x"25", x"10", x"62", x"00", x"f9", x"ff", x"43", x"24", 
	x"03", x"00", x"63", x"2c", x"12", x"00", x"60", x"10", 
	x"04", x"00", x"43", x"28", x"00", x"f0", x"04", x"3c", 
	x"00", x"10", x"05", x"3c", x"24", x"e8", x"24", x"01", 
	x"00", x"80", x"02", x"34", x"00", x"00", x"40", x"bc", 
	x"fe", x"ff", x"40", x"14", x"fc", x"ff", x"42", x"24", 
	x"25", x"f8", x"00", x"00", x"08", x"00", x"20", x"01", 
	x"21", x"e8", x"a5", x"03", x"b3", x"ff", x"00", x"10", 
	x"25", x"10", x"00", x"00", x"41", x"00", x"66", x"28", 
	x"ea", x"ff", x"c0", x"10", x"00", x"00", x"00", x"00", 
	x"e9", x"ff", x"00", x"10", x"d0", x"ff", x"63", x"24", 
	x"c8", x"ff", x"60", x"10", x"00", x"00", x"00", x"00", 
	x"21", x"10", x"42", x"00", x"c5", x"ff", x"00", x"10", 
	x"05", x"00", x"47", x"24", x"04", x"00", x"8d", x"14", 
	x"06", x"00", x"e3", x"28", x"21", x"10", x"42", x"00", 
	x"c0", x"ff", x"00", x"10", x"21", x"40", x"02", x"01", 
	x"a3", x"ff", x"60", x"14", x"03", x"ca", x"05", x"00", 
	x"05", x"00", x"e4", x"14", x"00", x"00", x"00", x"00", 
	x"9e", x"ff", x"20", x"15", x"25", x"28", x"40", x"00", 
	x"9c", x"ff", x"00", x"10", x"25", x"48", x"40", x"00", 
	x"2a", x"18", x"e4", x"00", x"9a", x"ff", x"60", x"10", 
	x"03", x"ca", x"05", x"00", x"01", x"00", x"83", x"30", 
	x"97", x"ff", x"60", x"10", x"2a", x"18", x"88", x"00", 
	x"95", x"ff", x"60", x"10", x"00", x"00", x"00", x"00", 
	x"00", x"00", x"a2", x"a0", x"91", x"ff", x"00", x"10", 
	x"01", x"00", x"a5", x"24", x"25", x"38", x"00", x"00", 
	x"25", x"28", x"00", x"00", x"25", x"10", x"00", x"00", 
	x"91", x"00", x"08", x"24", x"a0", x"00", x"09", x"24", 
	x"b1", x"00", x"0a", x"24", x"81", x"00", x"0b", x"24", 
	x"90", x"00", x"0c", x"24", x"80", x"00", x"0d", x"24", 
	x"00", x"48", x"03", x"40", x"02", x"1e", x"03", x"00", 
	x"10", x"ff", x"03", x"a0", x"04", x"fb", x"03", x"80", 
	x"01", x"00", x"63", x"30", x"fa", x"ff", x"60", x"10", 
	x"00", x"00", x"00", x"00", x"00", x"fb", x"03", x"80", 
	x"ff", x"00", x"63", x"30", x"0d", x"00", x"68", x"10", 
	x"92", x"00", x"64", x"2c", x"0f", x"00", x"80", x"10", 
	x"00", x"00", x"00", x"00", x"29", x"00", x"6b", x"10", 
	x"00", x"00", x"00", x"00", x"09", x"00", x"6c", x"10", 
	x"00", x"00", x"00", x"00", x"19", x"00", x"6d", x"10", 
	x"04", x"00", x"04", x"24", x"08", x"00", x"00", x"00", 
	x"00", x"00", x"00", x"00", x"ea", x"ff", x"00", x"10", 
	x"00", x"00", x"00", x"00", x"e8", x"ff", x"00", x"10", 
	x"25", x"10", x"a0", x"00", x"e6", x"ff", x"00", x"10", 
	x"25", x"38", x"a0", x"00", x"38", x"00", x"69", x"10", 
	x"00", x"00", x"00", x"00", x"f5", x"ff", x"6a", x"14", 
	x"00", x"00", x"00", x"00", x"00", x"f0", x"04", x"3c", 
	x"00", x"10", x"05", x"3c", x"24", x"e8", x"a4", x"00", 
	x"00", x"80", x"02", x"34", x"00", x"00", x"40", x"bc", 
	x"fe", x"ff", x"40", x"14", x"fc", x"ff", x"42", x"24", 
	x"25", x"f8", x"00", x"00", x"08", x"00", x"a0", x"00", 
	x"21", x"e8", x"a5", x"03", x"e9", x"ff", x"00", x"10", 
	x"00", x"00", x"00", x"00", x"00", x"2a", x"05", x"00", 
	x"04", x"fb", x"03", x"80", x"01", x"00", x"63", x"30", 
	x"fd", x"ff", x"60", x"10", x"00", x"00", x"00", x"00", 
	x"00", x"fb", x"03", x"80", x"ff", x"00", x"63", x"30", 
	x"ff", x"ff", x"84", x"24", x"f7", x"ff", x"80", x"14", 
	x"21", x"28", x"65", x"00", x"ca", x"ff", x"00", x"10", 
	x"00", x"00", x"00", x"00", x"25", x"20", x"40", x"00", 
	x"04", x"00", x"03", x"24", x"03", x"76", x"04", x"00", 
	x"04", x"fb", x"06", x"80", x"02", x"00", x"c6", x"30", 
	x"fd", x"ff", x"c0", x"14", x"00", x"00", x"00", x"00", 
	x"00", x"fb", x"0e", x"a0", x"ff", x"ff", x"63", x"24", 
	x"f8", x"ff", x"60", x"14", x"00", x"22", x"04", x"00", 
	x"bd", x"ff", x"00", x"10", x"00", x"00", x"00", x"00", 
	x"c2", x"17", x"02", x"00", x"25", x"10", x"44", x"00", 
	x"04", x"fb", x"04", x"80", x"01", x"00", x"84", x"30", 
	x"fd", x"ff", x"80", x"10", x"00", x"00", x"00", x"00", 
	x"00", x"fb", x"04", x"80", x"21", x"30", x"65", x"00", 
	x"00", x"00", x"c4", x"a0", x"ff", x"00", x"84", x"30", 
	x"21", x"10", x"82", x"00", x"01", x"00", x"63", x"24", 
	x"f3", x"ff", x"67", x"14", x"21", x"20", x"42", x"00", 
	x"ad", x"ff", x"00", x"10", x"00", x"00", x"00", x"00", 
	x"25", x"10", x"00", x"00", x"fa", x"ff", x"00", x"10", 
	x"25", x"18", x"00", x"00", x"00", x"00", x"00", x"00", 
	x"00", x"00", x"00", x"00", x"00", x"00", x"00", x"00", 
	x"00", x"00", x"00", x"00", x"00", x"00", x"00", x"00", 
	x"00", x"00", x"00", x"00", x"00", x"00", x"00", x"00", 
	x"00", x"00", x"00", x"00", x"00", x"00", x"00", x"00", 
	x"00", x"00", x"00", x"00", x"00", x"00", x"00", x"00", 
	x"00", x"00", x"00", x"00", x"00", x"00", x"00", x"00", 
	x"00", x"00", x"00", x"00", x"00", x"00", x"00", x"00", 
	x"00", x"00", x"00", x"00", x"00", x"00", x"00", x"00", 
	x"00", x"00", x"00", x"00", x"00", x"00", x"00", x"00", 
	x"00", x"00", x"00", x"00", x"00", x"00", x"00", x"00", 
	others => (others => '0')
    );

end boot_sio_mi32el;
