# FMADIO Ring Buffer Capture Plugin for Suricata
# Copyright 2025-2026. Fidelis Farm & Technologies, LLC

# Try to find Suricata via libsuricata-config (preferred), or use source tree
LIBSURICATA_CONFIG ?= libsuricata-config

# Check if libsuricata-config exists (for installed Suricata)
HAVE_LIBSURICATA_CONFIG := $(shell which $(LIBSURICATA_CONFIG) >/dev/null 2>&1 && echo yes || echo no)

ifeq ($(HAVE_LIBSURICATA_CONFIG),yes)
    SURICATA_CFLAGS := $(shell $(LIBSURICATA_CONFIG) --cflags)
    SURICATA_LIBS := $(shell $(LIBSURICATA_CONFIG) --libs)
else
    # Fallback: use local Suricata source tree (must be configured first!)
    SURICATA_SRC ?= /development/suricata
    SURICATA_CFLAGS := -I$(SURICATA_SRC)/src -I$(SURICATA_SRC) -DHAVE_CONFIG_H
    SURICATA_LIBS :=
    $(info Using Suricata source tree at $(SURICATA_SRC))
    $(info NOTE: Suricata must be configured (./configure) before building this plugin)
endif

# Compiler settings
CC ?= gcc
CFLAGS := -Wall -Wextra -fPIC -O2 $(SURICATA_CFLAGS)
# Suricata logging requires this macro
CPPFLAGS := "-D__SCFILENAME__=\"$(*F)\""
LDFLAGS := -shared $(SURICATA_LIBS) -lpthread -ldl

# Rust settings
CARGO ?= cargo
RUST_TARGET_DIR := target/release
RUST_LIB := $(RUST_TARGET_DIR)/libsuricata_fmadio_ring.a

# Output
PLUGIN_NAME := fmadio-ring.so
PLUGIN_DIR ?= /opt/suricata/lib

# Source files
C_SOURCES := plugin.c source.c runmode.c
C_OBJECTS := $(C_SOURCES:.c=.o)

.PHONY: all clean install rust-lib check test fmt clippy

all: $(PLUGIN_NAME)

# Build Rust static library (also generates header via build.rs)
rust-lib:
	$(CARGO) build --release

$(RUST_LIB): rust-lib

fmadio_ring_ffi.h: rust-lib

# Compile C objects
%.o: %.c fmadio_ring_ffi.h source.h runmode.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Link final plugin
$(PLUGIN_NAME): $(C_OBJECTS) $(RUST_LIB)
	$(CC) -o $@ $(C_OBJECTS) $(RUST_LIB) $(LDFLAGS)

install: $(PLUGIN_NAME)
	install -d $(DESTDIR)$(PLUGIN_DIR)
	install -m 755 $(PLUGIN_NAME) $(DESTDIR)$(PLUGIN_DIR)/

clean:
	rm -f $(C_OBJECTS) $(PLUGIN_NAME) fmadio_ring_ffi.h
	$(CARGO) clean

# Development helpers
check:
	$(CARGO) check

test:
	$(CARGO) test

fmt:
	$(CARGO) fmt

clippy:
	$(CARGO) clippy
