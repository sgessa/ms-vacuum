defmodule MsBot.Net.PacketHandler do
  require Log
  alias MsBot.{Crypto, Net}

  @ping <<0x11, 0x0>>
  @login_reply <<0x0, 0x0>>
  @login_process <<0x06, 0x0>>
  @show_worlds <<0x0A, 0x0>>
  @show_channels <<0x03, 0x0>>
  @channel_select <<0x14, 0x0>>
  @show_chars <<0x0B, 0x0>>
  @channel_info <<0x0C, 0x0>>
  @change_map <<0x5C, 0x0>>
  @show_mob <<0xAF, 0x0>>
  @show_drop_item <<0xCD, 0x0>>

  def serve(@ping, state) do
    Log.debug("Received ping packet", state.peer)
    pong = Net.PacketBuilder.pong()
    Log.debug("Sending pong packet", state.peer)
    write(pong, state)
  end

  def serve(<<@login_reply::little-bytes, _data::bytes>>, state) do
    Log.debug("Received login reply packet", state.peer)
    process_login = Net.PacketBuilder.process_login()
    Log.debug("Sending process login packet", state.peer)
    write(process_login, state)
  end

  def serve(<<@login_process::little-bytes, _data::bytes>>, state) do
    Log.debug("Received login process packet", state.peer)
    show_worlds = Net.PacketBuilder.show_worlds()
    Log.debug("Sending show worlds packet", state.peer)
    write(show_worlds, state)
  end

  def serve(<<@show_worlds::little-bytes, 0xFF>>, state) do
    Log.debug("Received show worlds end packet", state.peer)
    select_word = Net.PacketBuilder.select_world()
    Log.debug("Sending select world packet", state.peer)
    write(select_word, state)
  end

  def serve(<<@show_worlds::little-bytes, _data::bytes>>, state) do
    Log.debug("Received show worlds packet", state.peer)
    # We connect to the default world so we dont need to parse the packet
    {:ok, state}
  end

  def serve(<<@show_channels::little-bytes, _data::bytes>>, state) do
    Log.debug("Received show channels packet", state.peer)
    select_channel = Net.PacketBuilder.select_channel()
    Log.debug("Sending select channel packet", state.peer)
    write(select_channel, state)
  end

  def serve(<<@channel_select::little-bytes, _data::bytes>>, state) do
    Log.debug("Received channel select packet", state.peer)
    {:ok, state}
  end

  def serve(<<@show_chars::little-bytes, data::bytes>>, state) do
    <<0x0, _size::bytes-size(1), char_id::little-bytes-size(4), _data::bytes>> = data
    Log.debug("Received show characters packet", state.peer)
    channel_info = Net.PacketBuilder.channel_info(char_id)
    Log.debug("Sending get channel info packet", state.peer)
    write(channel_info, state)
  end

  def serve(<<@channel_info::little-bytes, data::bytes>>, state) do
    Log.debug("Received channel info packet", state.peer)

    <<_::bytes-size(2), addr::bytes-size(4), port::little-integer-size(16),
      char_id::little-bytes-size(4), _rest::bytes>> = data

    addr =
      addr
      |> :binary.bin_to_list()
      |> Enum.map(&to_string/1)
      |> Enum.join(".")

    MsBot.Net.Client.start_link({addr, port, %{peer: :channel, char_id: char_id}})

    {:ok, state}
  end

  def serve(<<@change_map::little-bytes, data::bytes>>, state) do
    Log.debug("Received change map packet", state.peer)
    <<_::bytes-size(115), char_pos::bytes-size(1), _::bytes>> = data
    {:ok, state}
  end

  def serve(<<@show_mob::little-bytes, data::bytes>>, state) do
    Log.debug("Received show mob packet", state.peer)
    <<mob_id::little-integer-size(32), _data::bytes>> = data
    mobs = [mob_id] ++ state.mobs
    {:ok, %{state | mobs: mobs}}
  end

  # def serve(<<@show_drop_item::little-bytes, data::bytes>>, state) do
  #   Log.debug("Received show drop item packet", state.peer)
  #
  #   <<0xCD, 0x0, 0x1, 0x9E, 0x10, 0x0, 0x0, 0x1, 0xA, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0,
  #     0x5C, 0xFF, 0xF7, 0xFE, 0x64, 0x0, 0x0, 0x0, 0x5C, 0xFF, 0x3B, 0xFF, 0x0, 0x0, 0x1>>
  #
  #   {:ok, state}
  # end

  def serve(data, state) do
    Log.debug("Received unknown packet: #{inspect(data, base: :hex)}", state.peer)
    {:ok, state}
  end

  def write(data, state) do
    {:ok, data, iv} = Crypto.Nif.encrypt(data, state.send_iv)
    {:ok, hdr} = Crypto.Nif.encrypt_hdr(iv, byte_size(data))
    :gen_tcp.send(state.socket, <<hdr::little-32>> <> data)
    {:ok, %{state | send_iv: iv}}
  end
end
