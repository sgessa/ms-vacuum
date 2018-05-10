defmodule MsBotTest do
  use ExUnit.Case
  doctest MsBot

  test "greets the world" do
    assert MsBot.hello() == :world
  end
end
