# Makefile — plpgsql_wrap
#
# Build:
#   make                                    # key from wrap_key.h
#   make WRAP_KEY_HEX=<64 hex chars>        # compile-time key override
#   make WRAP_KEY_HEX=$(openssl rand -hex 32)  # random key, one-liner
#
# Install:
#   sudo make install
#
# Tests:
#   make installcheck

MODULE_big = plpgsql_wrap
OBJS       = plpgsql_wrap.o
EXTENSION  = plpgsql_wrap
DATA       = $(wildcard updates/*--*.sql) $(wildcard sql/*.sql)
DOCS       = README.md

TESTS      =  01_basic 02_unwrap 03_replace 04_dump_restore 05_call_handler 06_security 07_upgrade
REGRESS      = $(patsubst test/sql/%.sql,%,$(TESTS))
REGRESS_OPTS = --inputdir=test

PG_CONFIG  ?= pg_config
PGXS       := $(shell $(PG_CONFIG) --pgxs)

OSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null || echo "")
OSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null || echo "-lssl -lcrypto")

PG_CFLAGS  += $(OSSL_CFLAGS) -Wall -Wextra -Wno-unused-parameter

# The key is never compiled in as a hex string literal: it is turned into
# masked byte arrays in wrap_key_data.h (see tools/gen_key_header.sh).
#
# - WRAP_KEY_HEX given (command line / environment): the header is
#   regenerated whenever that key differs from the one it holds.
# - otherwise: the key is read from wrap_key.h and the header is only
#   regenerated when wrap_key.h changes.  So "make WRAP_KEY_HEX=..." followed
#   by "sudo make install" keeps the key used at build time.
ifneq ($(filter command line environment,$(origin WRAP_KEY_HEX)),)
WRAP_KEY_DEP = FORCE
else
WRAP_KEY_HEX = $(shell sed -n 's/.*"\([0-9A-Fa-f]\{64\}\)".*/\1/p' wrap_key.h | head -1)
WRAP_KEY_DEP = wrap_key.h
endif

SHLIB_LINK += $(OSSL_LIBS)
EXTRA_CLEAN = wrap_key_data.h

include $(PGXS)

plpgsql_wrap.o: wrap_key_data.h

wrap_key_data.h: $(WRAP_KEY_DEP)
	@sh tools/gen_key_header.sh '$(WRAP_KEY_HEX)' $@

FORCE:

genkey:
	@openssl rand -hex 32

.PHONY: genkey FORCE
