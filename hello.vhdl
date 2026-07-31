entity hello is
end hello;
//我在测试芯片研发测试的英语是Pico test，日语是チップけんきゅうかいはつ・テスト吗//
architecture behav of hello is
begin
  assert false report "Hello VHDL world" severity note;
end behav;
