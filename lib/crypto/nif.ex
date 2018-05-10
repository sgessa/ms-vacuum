defmodule MsBot.Crypto.Nif do
  @on_load :load_nifs

  app = Mix.Project.config()[:app]

  def load_nifs do
    path = :filename.join(:code.priv_dir(unquote(app)), 'ms_crypto')
    :ok = :erlang.load_nif(path, 0)
  end

  def encrypt_hdr(_send_iv, _packet_len) do
    raise "NIF encrypt_hdr/2 not implemented"
  end

  def encrypt(_packet, _send_iv) do
    raise "NIF encrypt/2 not implemented"
  end

  def decrypt(_packet, _recv_iv) do
    raise "NIF decrypt/2 not implemented"
  end
end
