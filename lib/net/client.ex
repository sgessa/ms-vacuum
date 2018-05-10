defmodule MsBot.Net.Client do
  import Bitwise
  alias MsBot.Net

  @default_state %{
    peer: :login,
    handshake: true,
    send_iv: nil,
    recv_iv: nil,
    ms_version: nil,
    char_id: nil,
    mobs: [],
    vacuum: false
  }

  def start_link({_host, _port, opts} = args) do
    name = opts[:peer] || :login
    GenServer.start_link(__MODULE__, args, name: name)
  end

  def init({host, port, opts}) do
    host = to_charlist(host)

    case :gen_tcp.connect(host, port, [:binary, packet: 0, active: false]) do
      {:ok, socket} ->
        state =
          @default_state
          |> Map.merge(opts)
          |> Map.put(:socket, socket)

        Log.info("Connected", state.peer)

        # Read Handshake packet
        pid = self()
        recv(socket, 0, pid)

        Task.start_link(fn -> loop_recv(socket, pid) end)

        {:ok, state}

      error ->
        error
    end
  end

  def handle_info({:vacuum, :stop}, state) do
    {:noreply, %{state | vacuum: false}}
  end

  def handle_info({:vacuum, :start}, state) do
    send(self(), :vacuum)
    {:noreply, %{state | vacuum: true}}
  end

  def handle_info(:vacuum, state) do
    if state.vacuum do
      {:ok, state} = MsBot.Vacuum.run(state)
      Process.send_after(self(), :vacuum, 1000)
      {:noreply, state}
    else
      {:noreply, state}
    end
  end

  def handle_info({:tcp, packet}, %{handshake: true} = state) do
    Log.debug("Received handshake packet: #{inspect(packet, base: :hex)}", state.peer)

    state =
      case state.peer do
        :login ->
          perform_login(packet, state)

        :channel ->
          perform_channel_login(packet, state)
      end

    {:noreply, %{state | handshake: false}}
  end

  # Encrypted Packets
  def handle_info({:tcp, data}, state) do
    {:ok, data, recv_iv} = MsBot.Crypto.Nif.decrypt(data, state.recv_iv)
    {:ok, state} = Net.PacketHandler.serve(data, state)
    {:noreply, %{state | recv_iv: recv_iv}}
  end

  defp perform_login(data, state) do
    <<_::bytes-size(2), ver::little-integer-size(16), _subver::bytes-size(3),
      send_iv::little-bytes-size(4), recv_iv::little-bytes-size(4), _locale::bytes>> = data

    state = %{state | send_iv: send_iv, recv_iv: recv_iv, ms_version: ver}

    Log.debug("Performing login", state.peer)

    {:ok, state} =
      Net.PacketBuilder.login()
      |> Net.PacketHandler.write(state)

    state
  end

  defp perform_channel_login(data, state) do
    <<_::bytes-size(2), ver::little-integer-size(16), _empty::bytes-size(2),
      send_iv::little-bytes-size(4), recv_iv::little-bytes-size(4), _locale::bytes>> = data

    state = %{state | send_iv: send_iv, recv_iv: recv_iv, ms_version: ver}

    Log.debug("Performing login", state.peer)

    {:ok, state} =
      Net.PacketBuilder.channel_login(state.char_id)
      |> Net.PacketHandler.write(state)

    state
  end

  defp loop_recv(socket, pid) do
    length = recv_hdr(socket)
    recv(socket, length, pid)
    loop_recv(socket, pid)
  end

  defp recv_hdr(socket) do
    {:ok, <<hdr::little-integer-size(32)>>} = :gen_tcp.recv(socket, 4)
    (hdr &&& 0x0000FFFF) ^^^ (hdr >>> 16)
  end

  defp recv(socket, length, pid) do
    {:ok, data} = :gen_tcp.recv(socket, length)
    send(pid, {:tcp, data})
  end
end
