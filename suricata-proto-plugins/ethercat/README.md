# Suricata EtherCAT Parser Plugin

Application-layer parser plugin for Suricata that decodes the EtherCAT (Ethernet for Control Automation Technology) industrial protocol (EtherType 0x88A4).

## What It Parses

EtherCAT is a high-performance industrial Ethernet protocol used in:
- **Industrial automation** — PLC communication, I/O modules
- **Motion control** — Servo drives, stepper motors
- **Robotics** — Real-time fieldbus communication
- **Process control** — Distributed I/O

The plugin parses:
- EtherCAT frame headers (length, type)
- Datagram headers (command, slave address, working counter)
- Command types (APRD, FPWR, LRW, BRD, etc.)
- Mailbox protocol detection (CoE, EoE, FoE, SoE, AoE)
- Cyclic vs. acyclic traffic classification

## EVE JSON Output

```json
{
  "timestamp": "2026-04-25T10:00:00.000000+0000",
  "event_type": "ethercat",
  "ethercat": {
    "frame_type": 1,
    "frame_type_name": "Command",
    "frame_length": 44,
    "datagram_count": 2,
    "is_cyclic": true,
    "has_mailbox": false,
    "datagrams": [
      {
        "command": 12,
        "command_name": "LRW",
        "slave_address": 4096,
        "data_length": 32,
        "working_counter": 2,
        "is_cyclic": true
      }
    ]
  }
}
```

## Suricata Rules

```
# Alert on EtherCAT broadcast writes
alert udp any any -> any any (msg:"EtherCAT Broadcast Write"; app-layer-protocol:ethercat; content:"BWR"; sid:5000001; rev:1;)

# Alert on EtherCAT mailbox traffic
alert udp any any -> any any (msg:"EtherCAT Mailbox"; app-layer-protocol:ethercat; ethercat.has_mailbox; sid:5000002; rev:1;)
```

## Building

```bash
# With Suricata source tree
SURICATA_SRC=/path/to/suricata make

# Run Rust unit tests (no Suricata dependency)
make test
```

## Architecture

```
src/
├── lib.rs         # Suricata FFI bridge (C-extern callbacks)
├── ethercat.rs    # Pure Rust EtherCAT wire protocol parser
├── state.rs       # Per-flow state and transaction management
└── logger.rs      # EVE JSON generation

plugin.c           # Suricata plugin entry point (SCPluginRegister)
applayer.c         # App-layer registration and callback routing
ethercat-plugin.h  # C header for plugin metadata
Makefile           # Build orchestration
```

## References

- [IEC 61158-4-12 — EtherCAT Data Link Layer](https://www.iec.ch/)
- [EtherCAT Technology Group](https://www.ethercat.org/)
- [Suricata App-Layer Template](https://github.com/OISF/suricata/tree/master/rust/src/applayertemplate)

## License

GPL-2.0-only (matching Suricata's license)
