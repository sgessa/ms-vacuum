defmodule MsBot.Supervisor do
  use Supervisor

  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, :ok, opts)
  end

  def init(:ok) do
    config = Application.get_env(:ms_bot, :server)

    children = [
      worker(MsBot.Net.Client, [{config[:address], config[:port], %{}}])
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  # MsBot.Net.Client.start_link({"127.0.0.1", 8484, %{}})
end
