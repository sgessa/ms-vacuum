# MS Bot

Headless MapleStory Bot for v62.

Currently only GNU/Linux and FreeBSD are supported.

Tested on [Vana Server](https://github.com/retep998/Vana/tree/62_support).

# Getting started

1) Fetch dependencies

`mix deps.get`

2) Configuration

open `config/config.exs` and configure server and account settings

3) Open IEx

`iex -S mix`

4) Vacuum

To start using vacuum run:

`> MsBot.start_vacuum`

To stop using vacuum:

`> MsBot.stop_vacuum`
