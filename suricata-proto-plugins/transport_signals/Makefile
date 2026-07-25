# Rockfish Suricata Transport Signals Plugin - Makefile
# Copyright 2025-2026. Fidelis Farm & Technologies, LLC
# SPDX-License-Identifier: GPL-2.0-only

PLUGIN_NAME = rockfish-transport-signals

LIBSURICATA_CONFIG = $(shell which libsuricata-config 2>/dev/null)

ifneq ($(LIBSURICATA_CONFIG),)
    SURICATA_CFLAGS = $(shell $(LIBSURICATA_CONFIG) --cflags)
    SURICATA_LDFLAGS = $(shell $(LIBSURICATA_CONFIG) --libs)
else ifdef SURICATA_SRC
    SURICATA_CFLAGS = -I$(SURICATA_SRC)/src -I$(SURICATA_SRC) -I$(SURICATA_SRC)/rust/gen -DHAVE_CONFIG_H '-D__SCFILENAME__=""'
    SURICATA_LDFLAGS =
else
    SURICATA_SRC = /development/suricata
    SURICATA_CFLAGS = -I$(SURICATA_SRC)/src -I$(SURICATA_SRC) -I$(SURICATA_SRC)/rust/gen -DHAVE_CONFIG_H '-D__SCFILENAME__=""'
    SURICATA_LDFLAGS =
endif

CC = cc
CFLAGS = -Wall -Wextra -fPIC -O2 $(SURICATA_CFLAGS)
LDFLAGS = -shared $(SURICATA_LDFLAGS) -lpthread -ldl -lm

CARGO = cargo
CARGO_FLAGS = --release
RUST_LIB = target/release/libsuricata_transport_signals.a

C_SOURCES = plugin.c output.c
C_OBJECTS = $(C_SOURCES:.c=.o)

PLUGIN_SO = $(PLUGIN_NAME).so

.PHONY: all clean rust rust-clean

all: $(PLUGIN_SO)

rust:
	$(CARGO) build $(CARGO_FLAGS)

$(RUST_LIB): rust

%.o: %.c transport-signals.h
	$(CC) $(CFLAGS) -c $< -o $@

$(PLUGIN_SO): $(C_OBJECTS) $(RUST_LIB)
	$(CC) -o $@ $(C_OBJECTS) $(RUST_LIB) $(LDFLAGS)

clean: rust-clean
	rm -f $(C_OBJECTS) $(PLUGIN_SO) transport_signals_ffi.h

rust-clean:
	$(CARGO) clean

# Install the already-built .so without re-checking dependencies.
# Run `make` first if you want a rebuild before installing.
.PHONY: install
install:
	@test -f $(PLUGIN_SO) || { echo "$(PLUGIN_SO) not found — run 'make' first" >&2; exit 1; }
	install -d $(DESTDIR)/usr/lib/suricata/plugins
	install -m 755 $(PLUGIN_SO) $(DESTDIR)/usr/lib/suricata/plugins/

.PHONY: test
test: $(PLUGIN_SO)
	@echo "Plugin built successfully: $(PLUGIN_SO)"
	@ls -la $(PLUGIN_SO)
