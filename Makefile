ERLANG_PATH = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)

CFLAGS = -fPIC -O3 -shared -I$(ERLANG_PATH)

SRC = src/ms_crypto.c
NIF = priv/ms_crypto.so

all: priv $(NIF)

priv:
	mkdir -p priv

$(NIF): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

clean:
	$(RM) $(NIF)
