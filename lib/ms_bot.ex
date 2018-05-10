defmodule MsBot do
  use Application

  def start(_type, _args) do
    MsBot.Supervisor.start_link()
  end

  def start_vacuum() do
    send(:channel, {:vacuum, :start})
  end

  def stop_vacuum() do
    send(:channel, {:vacuum, :stop})
  end
end
