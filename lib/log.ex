defmodule Log do
  require Logger

  def info(msg, peer) do
    Logger.info("[#{peer}] #{msg}")
  end

  def debug(msg, peer) do
    Logger.debug("[#{peer}] #{msg}")
  end

  def error(msg, peer) do
    Logger.error("[#{peer}] #{msg}")
  end
end
