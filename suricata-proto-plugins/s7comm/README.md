# Suricata S7comm Parser Plugin

Application-layer parser plugin for Suricata that decodes the S7comm protocol used by Siemens S7 PLCs over TPKT/COTP on TCP port 102.

## What It Parses

S7comm is the native protocol for Siemens SIMATIC S7 PLCs (S7-300, S7-400, S7-1200, S7-1500). The protocol runs over ISO-on-TCP (RFC 1006) using TPKT + COTP transport.

The plugin parses:
- TPKT headers (version, length)
- COTP headers (PDU type: CR, CC, DT Data)
- S7comm headers (protocol ID, message type, PDU reference)
- Function codes (Setup, ReadVar, WriteVar, Download, Upload, PlcControl, PlcStop)
- Memory area identifiers (Inputs, Outputs, Flags, Data Blocks, etc.)
- S7comm+ detection (extended protocol, magic 0x72)

## EVE JSON Output

```json
{
  "timestamp": "2026-04-25T10:00:00.000000+0000",
  "event_type": "s7comm",
  "src_ip": "10.0.4.100",
  "dest_ip": "10.0.4.200",
  "src_port": 49152,
  "dest_port": 102,
  "proto": "TCP",
  "s7comm": {
    "cotp_pdu_type": "DT_DATA",
    "msg_type": "Job",
    "function_code": "ReadVar",
    "area": "DB",
    "db_number": 1,
    "is_s7comm_plus": false,
    "is_security_relevant": false,
    "pdu_ref": 1,
    "param_length": 14,
    "data_length": 0
  }
}
```

## Suricata Rules

```
# Alert on S7comm PLC stop command
alert tcp any any -> any 102 (msg:"S7comm PLC Stop"; app-layer-protocol:s7comm; s7comm.function_code:0x29; sid:5000001; rev:1;)

# Alert on S7comm write operations
alert tcp any any -> any 102 (msg:"S7comm Write Variable"; app-layer-protocol:s7comm; s7comm.function_code:0x05; sid:5000002; rev:1;)

# Alert on S7comm download to PLC
alert tcp any any -> any 102 (msg:"S7comm Program Download"; app-layer-protocol:s7comm; s7comm.function_code:0x1A; sid:5000003; rev:1;)
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
├── lib.rs       # Suricata FFI bridge (C-extern callbacks)
├── s7comm.rs    # Pure Rust S7comm wire protocol parser
├── state.rs     # Per-flow state and transaction management
└── logger.rs    # EVE JSON generation

plugin.c         # Suricata plugin entry point (SCPluginRegister)
applayer.c       # App-layer registration and callback routing
s7comm-plugin.h  # C header for plugin metadata
Makefile         # Build orchestration
```

## License

GPL-2.0-only (matching Suricata's license)
