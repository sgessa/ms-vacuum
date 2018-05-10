defmodule MsBot.Vacuum do
  alias MsBot.Net

  def run(state) do
    with {:ok, state} <- move_player(state),
         {:ok, state} <- control_mobs(state),
         {:ok, state} <- attack_mobs(state) do
      {:ok, %{state | mobs: []}}
    else
      err ->
        Log.error("Vacuum error: #{inspect(err)}")
        {:ok, %{state | vacuum: false}}
    end
  end

  def move_player(state) do
    Net.PacketBuilder.move_player()
    |> Net.PacketHandler.write(state)
  end

  def control_mobs(state) do
    state =
      Enum.reduce(state.mobs, state, fn mob_id, acc ->
        {:ok, acc} =
          Net.PacketBuilder.control_mob(mob_id)
          |> Net.PacketHandler.write(acc)

        :timer.sleep(50)

        acc
      end)

    {:ok, state}
  end

  def attack_mobs(state) do
    state =
      Enum.reduce(state.mobs, state, fn mob_id, acc ->
        {:ok, acc} =
          Net.PacketBuilder.attack(mob_id)
          |> Net.PacketHandler.write(acc)

        :timer.sleep(50)

        acc
      end)

    {:ok, state}
  end
end
