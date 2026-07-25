# FMADIO Ring Buffer Capture Plugin for Suricata

A Suricata capture plugin that reads packets from FMADIO devices via their
shared memory ring buffer interface. Designed for high-speed packet capture
on FMADIO devices, typically running inside LXC containers.

## Overview

This plugin enables Suricata to acquire packets directly from FMADIO's shared
memory ring buffer (`/opt/fmadio/queue/lxc_ring*`), providing efficient
zero-copy packet capture at high speeds.

## Requirements

- Suricata 8.0+ (with plugin support enabled)
- Rust 1.70+ and Cargo
- GCC or Clang
- Access to FMADIO ring buffer files

## Building

### Option 1: Against Installed Suricata

If Suricata is installed with development files:

```bash
make
sudo make install
```

The Makefile will use `libsuricata-config` to find include paths.

### Option 2: Against Suricata Source Tree

If building against a Suricata source tree:

```bash
# First, configure Suricata (if not already done)
cd /path/to/suricata
./configure --enable-plugins

# Then build the plugin
cd /path/to/suricata-plugin-fmadio-ring
make SURICATA_SRC=/path/to/suricata
```

### Build Options

| Variable | Default | Description |
|----------|---------|-------------|
| `SURICATA_SRC` | `/development/suricata` | Path to Suricata source tree |
| `PLUGIN_DIR` | `/opt/suricata/lib` | Installation directory |
| `CC` | `gcc` | C compiler |
| `CARGO` | `cargo` | Rust build tool |

Example with custom paths:

```bash
make SURICATA_SRC=/home/user/suricata PLUGIN_DIR=/usr/local/lib/suricata
```

## Installation

```bash
sudo make install
# Installs to /opt/suricata/lib/fmadio-ring.so
```

Or install to a custom location:

```bash
make install PLUGIN_DIR=/usr/lib/suricata/plugins
```

## Configuration

### suricata.yaml

Add the plugin to your Suricata configuration:

```yaml
plugins:
  - /opt/suricata/lib/fmadio-ring.so
```

### Multiple Ring Buffers

Configure multiple ring buffers in `suricata.yaml` (one worker thread per ring):

```yaml
fmadio-ring:
  - ring: /opt/fmadio/queue/lxc_ring0
  - ring: /opt/fmadio/queue/lxc_ring1
  - ring: /opt/fmadio/queue/lxc_ring2
```

### Command Line

Run Suricata with the FMADIO Ring capture plugin:

```bash
# Single ring via command line
suricata --capture-plugin fmadio-ring \
         --capture-plugin-args "/opt/fmadio/queue/lxc_ring0" \
         -c /etc/suricata/suricata.yaml

# Multiple rings via YAML (no --capture-plugin-args needed)
suricata --capture-plugin fmadio-ring \
         -c /etc/suricata/suricata.yaml
```

**Priority**: YAML configuration takes precedence over `--capture-plugin-args`.
If no configuration is found, defaults to `/opt/fmadio/queue/lxc_ring0`.

## Ring Buffer Format

The plugin reads from FMADIO's shared memory ring buffer with the following
structure:

- **Header**: 3 x 4KB pages (metadata, put pointer, get pointer)
- **Entries**: 1024 x 12KB packet entries
- **Total Size**: 16MB mapped region

Each packet entry contains:
- 64-bit nanosecond timestamp
- Wire length and capture length
- Port number and flags (EOF, FCS error)
- Up to 10KB payload

## Statistics

The plugin registers per-ring counters (where `N` is the ring ID extracted from the path):

- `capture.fmadio_ringN.packets` - Packets received
- `capture.fmadio_ringN.bytes` - Bytes received
- `capture.fmadio_ringN.drops` - Packets dropped

For example, with rings `lxc_ring0` and `lxc_ring1`:

```
capture.fmadio_ring0.packets
capture.fmadio_ring0.bytes
capture.fmadio_ring0.drops
capture.fmadio_ring1.packets
capture.fmadio_ring1.bytes
capture.fmadio_ring1.drops
```

View with: `suricatasc -c "dump-counters" | grep fmadio`

## Development

```bash
# Check Rust code
make check

# Run Rust tests
make test

# Format code
make fmt

# Run clippy lints
make clippy
```

## License

GPL-2.0-only

## References

- [FMADIO Platform](https://github.com/fmadio/platform)
- [FMADIO Ring Documentation](https://docs.fmad.io/docs/fmadio-os-internal-fmadio-ring)
- [Suricata Plugin Documentation](https://docs.suricata.io/en/latest/plugins.html)
