# Suricata CANopen Parser Plugin

Application-layer parser plugin for Suricata that decodes the CANopen protocol transported over CAN-over-UDP encapsulation, common in automotive, robotics, and industrial test environments.

## What It Parses

CANopen is a CAN-based higher-layer protocol used in:
- **Industrial automation** — PLC communication, I/O modules
- **Robotics** — Joint controllers, sensor interfaces
- **Medical devices** — Equipment communication
- **Automotive testing** — CAN bus monitoring over Ethernet

The plugin parses:
- CAN-over-UDP encapsulation headers
- COB-ID decomposition (function code + node ID)
- NMT commands (Start, Stop, Reset Node, Reset Communication)
- SDO transfers (read/write object dictionary, index/subindex)
- PDO data objects (TPDO1-4, RPDO1-4)
- Emergency frames (EMCY)
- Heartbeat / NMT Error Control
- SYNC frames

## EVE JSON Output

```json
{
  "timestamp": "2026-04-25T10:00:00.000000+0000",
  "event_type": "canopen",
  "canopen": {
    "sequence": 1,
    "frame_count": 1,
    "has_nmt": false,
    "has_sdo": true,
    "has_pdo": false,
    "has_emergency": false,
    "frames": [
      {
        "cob_id": 1537,
        "node_id": 1,
        "function_code": "RSDO",
        "function_name": "RSDO",
        "dlc": 8,
        "data_hex": "2340600006000000",
        "sdo_command": "InitiateDownloadReq",
        "sdo_index": 24640,
        "sdo_subindex": 0
      }
    ]
  }
}
```

## Suricata Rules

```
# Alert on NMT Reset Node commands
alert udp any any -> any any (msg:"CANopen NMT Reset Node"; app-layer-protocol:canopen; canopen.has_nmt; sid:6000001; rev:1;)

# Alert on CANopen emergency frames
alert udp any any -> any any (msg:"CANopen Emergency"; app-layer-protocol:canopen; canopen.has_emergency; sid:6000002; rev:1;)

# Alert on SDO write operations
alert udp any any -> any any (msg:"CANopen SDO Write"; app-layer-protocol:canopen; canopen.has_sdo; sid:6000003; rev:1;)
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
├── lib.rs        # Suricata FFI bridge (C-extern callbacks)
├── canopen.rs    # Pure Rust CANopen wire protocol parser
├── state.rs      # Per-flow state and transaction management
└── logger.rs     # EVE JSON generation

plugin.c          # Suricata plugin entry point (SCPluginRegister)
applayer.c        # App-layer registration and callback routing
canopen-plugin.h  # C header for plugin metadata
Makefile          # Build orchestration
```

## References

- [CiA 301 — CANopen Application Layer](https://www.can-cia.org/)
- [CiA 302 — CANopen Framework](https://www.can-cia.org/)
- [Suricata App-Layer Template](https://github.com/OISF/suricata/tree/master/rust/src/applayertemplate)

## License

GPL-2.0-only (matching Suricata's license)
