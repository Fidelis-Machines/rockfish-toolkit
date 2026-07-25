# Rockfish S7comm Parser Plugin — Makefile
# Copyright 2025-2026. Fidelis Farm & Technologies, LLC
# SPDX-License-Identifier: GPL-2.0-only

PLUGIN_NAME = rockfish-s7comm-parser

# Try to find Suricata via libsuricata-config, fall back to source tree
LIBSURICATA_CONFIG = $(shell which libsuricata-config 2>/dev/null)

ifneq ($(LIBSURICATA_CONFIG),)
    SURICATA_CFLAGS = $(shell $(LIBSURICATA_CONFIG) --cflags)
    SURICATA_LDFLAGS = $(shell $(LIBSURICATA_CONFIG) --libs)
else ifdef SURICATA_SRC
    $(info Using Suricata source tree at $(SURICATA_SRC))
    SURICATA_CFLAGS = -I$(SURICATA_SRC)/src -I$(SURICATA_SRC) -I$(SURICATA_SRC)/rust/gen -DHAVE_CONFIG_H '-D__SCFILENAME__=""'
    SURICATA_LDFLAGS =
else
    SURICATA_SRC = /development/suricata
    $(info Using Suricata source tree at $(SURICATA_SRC))
    SURICATA_CFLAGS = -I$(SURICATA_SRC)/src -I$(SURICATA_SRC) -I$(SURICATA_SRC)/rust/gen -DHAVE_CONFIG_H '-D__SCFILENAME__=""'
    SURICATA_LDFLAGS =
endif

# Compiler settings
CC = cc
CFLAGS = -Wall -Wextra -fPIC -O2 $(SURICATA_CFLAGS)
LDFLAGS = -shared $(SURICATA_LDFLAGS) -lpthread -ldl -lm

# Rust settings
CARGO = cargo
CARGO_FLAGS = --release
RUST_LIB = target/release/libsuricata_s7comm_parser.a

# Source files
C_SOURCES = plugin.c applayer.c
C_OBJECTS = $(C_SOURCES:.c=.o)

# Output
PLUGIN_SO = $(PLUGIN_NAME).so

.PHONY: all clean rust rust-clean install test

all: $(PLUGIN_SO)

# Build Rust static library
rust:
	$(CARGO) build $(CARGO_FLAGS)

$(RUST_LIB): rust

# Compile C sources
%.o: %.c s7comm-plugin.h
	$(CC) $(CFLAGS) -c $< -o $@

# Link everything together
$(PLUGIN_SO): $(C_OBJECTS) $(RUST_LIB)
	$(CC) -o $@ $(C_OBJECTS) $(RUST_LIB) $(LDFLAGS)

clean: rust-clean
	rm -f $(C_OBJECTS) $(PLUGIN_SO) s7comm_parser_ffi.h

rust-clean:
	$(CARGO) clean

# Install to Suricata plugin directory
install: $(PLUGIN_SO)
	install -d $(DESTDIR)/usr/lib/suricata/plugins
	install -m 755 $(PLUGIN_SO) $(DESTDIR)/usr/lib/suricata/plugins/

# Rust tests only (no Suricata dependency)
test:
	$(CARGO) test

.PHONY: check
check: $(PLUGIN_SO)
	@echo "Plugin built successfully: $(PLUGIN_SO)"
	@ls -la $(PLUGIN_SO)
	@echo ""
	@echo "Install with: sudo make install"
	@echo "Then add to suricata.yaml:"
	@echo "  plugins:"
	@echo "    - /usr/lib/suricata/plugins/$(PLUGIN_SO)"
