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

TESTS      =  01_basic 02_unwrap 03_replace 04_dump_restore
REGRESS      = $(patsubst test/sql/%.sql,%,$(TESTS))
REGRESS_OPTS = --inputdir=test

PG_CONFIG  ?= pg_config
PGXS       := $(shell $(PG_CONFIG) --pgxs)

OSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null || echo "")
OSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null || echo "-lssl -lcrypto")

PG_CFLAGS  += $(OSSL_CFLAGS) -Wall -Wextra -Wno-unused-parameter

ifdef WRAP_KEY_HEX
PG_CFLAGS  += -DWRAP_KEY_HEX='"$(WRAP_KEY_HEX)"'
endif

SHLIB_LINK += $(OSSL_LIBS)

include $(PGXS)

genkey:
	@openssl rand -hex 32

.PHONY: genkey
