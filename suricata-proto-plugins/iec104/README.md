# Suricata IEC 60870-5-104 Parser Plugin

Application-layer parser plugin for Suricata that decodes the IEC 60870-5-104 (IEC 104) telecontrol protocol used in power grid SCADA systems.

## What It Parses

IEC 104 is the TCP transport profile of IEC 60870-5-101, used for telecontrol communication between control stations and substations in electrical power systems. It runs over TCP port 2404.

The plugin parses:
- APCI headers (start byte, length, control field)
- I-frames (Information transfer — carries ASDU payload)
- S-frames (Supervisory — flow control acknowledgements)
- U-frames (Unnumbered — connection management: STARTDT, STOPDT, TESTFR)
- ASDU contents (type ID, cause of transmission, common address, IOA addresses)
- Command detection (single/double commands, set-points, system commands)

## EVE JSON Output

```json
{
  "timestamp": "2026-04-25T10:00:00.000000+0000",
  "event_type": "iec104",
  "src_ip": "10.0.1.100",
  "dest_ip": "10.0.1.1",
  "src_port": 49152,
  "dest_port": 2404,
  "proto": "TCP",
  "iec104": {
    "apdu_count": 1,
    "apdus": [
      {
        "frame_type": "I",
        "send_seq": 0,
        "recv_seq": 0,
        "asdu": {
          "type_id": 100,
          "type_name": "C_IC_NA (Interrogation)",
          "is_command": true,
          "cot": "activation",
          "common_address": 1,
          "num_objects": 1,
          "ioas": [0]
        }
      }
    ]
  }
}
```

## Suricata Rules

Example detection rules using the IEC 104 parser:

```
# Alert on any IEC 104 command (control direction)
alert tcp any any -> any 2404 (msg:"IEC 104 Command Detected"; app-layer-protocol:iec104; iec104.is_command; sid:5000001; rev:1;)

# Alert on direct control actions (switches, set-points)
alert tcp any any -> any 2404 (msg:"IEC 104 Control Action"; app-layer-protocol:iec104; iec104.is_control_action; sid:5000002; rev:1;)

# Alert on system management commands (interrogation, clock sync, reset)
alert tcp any any -> any 2404 (msg:"IEC 104 System Command"; app-layer-protocol:iec104; iec104.is_system_command; sid:5000003; rev:1;)

# Alert on U-frame control functions (STARTDT/STOPDT)
alert tcp any any -> any 2404 (msg:"IEC 104 U-Frame Control"; app-layer-protocol:iec104; iec104.has_u_control; sid:5000004; rev:1;)
```

## ASDU Type IDs

| Range | Direction | Description |
|-------|-----------|-------------|
| 1-44 | Monitoring | Process information (single/double-point, measured values) |
| 45-69 | Control | Direct control actions (commands, set-points) |
| 100-106 | System | System management (interrogation, clock sync, reset) |
| 120-127 | File | File transfer operations |

## Building

### Prerequisites

- Rust toolchain (1.70+)
- Suricata source tree or `libsuricata-config` installed
- C compiler (gcc/clang)

### Build

```bash
# With Suricata source tree
SURICATA_SRC=/path/to/suricata make

# With installed Suricata (libsuricata-config in PATH)
make

# Run Rust unit tests (no Suricata dependency)
make test
```

### Install

```bash
sudo make install
```

This copies `rockfish-iec104-parser.so` to `/usr/lib/suricata/plugins/`.

### Configure Suricata

Add to `suricata.yaml`:

```yaml
plugins:
  - /usr/lib/suricata/plugins/rockfish-iec104-parser.so

app-layer:
  protocols:
    iec104:
      enabled: yes
```

## Architecture

```
src/
├── lib.rs       # Suricata FFI bridge (C-extern callbacks)
├── iec104.rs    # Pure Rust IEC 104 wire protocol parser
├── state.rs     # Per-flow state and transaction management
└── logger.rs    # EVE JSON generation

plugin.c         # Suricata plugin entry point (SCPluginRegister)
applayer.c       # App-layer registration and callback routing
iec104-plugin.h  # C header for plugin metadata
Makefile         # Build orchestration
```

The IEC 104 parser (`iec104.rs`) is intentionally independent of Suricata so it can be reused in other contexts (e.g., direct PCAP analysis in rockfish-parser).

## Security Use Cases

### OT/ICS Power Grid Monitoring
- Detect unauthorized control commands to substations
- Alert on set-point changes to breakers and switches
- Monitor clock synchronization commands for time manipulation
- Detect reset process commands that could disrupt operations

### SCADA Network Security
- Inventory all IEC 104 communication flows
- Alert on commands from unexpected source addresses
- Monitor U-frame patterns for connection hijacking
- Detect interrogation storms (reconnaissance)

### Network Forensics
- Track command/response sequences
- Reconstruct control actions timeline
- Detect anomalous common address usage
- Monitor IOA access patterns

## References

- [IEC 60870-5-104:2006](https://webstore.iec.ch/publication/3746) — Telecontrol equipment and systems, TCP/IP transport
- [Suricata App-Layer Template](https://github.com/OISF/suricata/tree/master/rust/src/applayertemplate)
- [Suricata Rust Crate](https://docs.rs/suricata/latest/suricata/)

## License

GPL-2.0-only (matching Suricata's license)
