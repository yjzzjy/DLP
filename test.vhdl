-------------------------------------------------------------------------------
-- File        : test.vhdl
-- Description : VHDL example -- parameterized 2-input logic gate
-- Standard    : VHDL-2008
-- Note        : .vhdl and .vhd are the same format (VHDL source), only the
--               file extension differs.
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;

entity gate2 is
    generic (
        G_AND : boolean := true       -- true: AND, false: OR
    );
    port (
        a : in  std_logic;
        b : in  std_logic;
        y : out std_logic
    );
end entity gate2;

architecture behavioral of gate2 is
begin

    y <= (a and b) when G_AND else (a or b);

end architecture behavioral;
