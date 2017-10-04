R2_PLUGIN_PATH=$(shell r2 -hh|grep LIBR_PLUGINS|awk '{print $$2}')
CFLAGS_IO=-g -fPIC $(shell pkg-config --cflags r_io)
LDFLAGS_IO=-shared $(shell pkg-config --libs r_io)
CFLAGS_BIN=-g -fPIC $(shell pkg-config --cflags r_bin)
LDFLAGS_BIN=-shared $(shell pkg-config --libs r_bin)
EXT_SO=$(shell r2 -hh|grep LIBEXT|awk '{print $$2}')
SUDO=sudo

CC_IO=$(CC) $(CFLAGS_IO) $(LDFLAGS_IO)
CC_BIN=$(CC) $(CFLAGS_BIN) $(LDFLAGS_BIN)

all:
	$(CC_IO) -o io_ggpack.$(EXT_SO) io_ggpack.c
	$(CC_BIN) -o bin_ggpack.$(EXT_SO) bin_ggpack.c

install: all
	$(SUDO) cp -f *.$(EXT_SO) $(R2_PLUGIN_PATH)

uninstall:
	for a in *.$(EXT_SO) ; do rm -f $(R2_PLUGIN_PATH)/$$a ; done

clean:
	rm -f *.$(EXT_SO)
	rm -rf *.$(EXT_SO).dSYM
