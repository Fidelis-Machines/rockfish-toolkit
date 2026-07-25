# Suricata IEC 61850 MMS Parser Plugin

Application-layer parser plugin for Suricata that decodes IEC 61850 MMS (Manufacturing Message Specification) protocol used for substation automation and power grid SCADA communication.

## What It Parses

IEC 61850 is the international standard for communication in electrical substations. The MMS protocol carries IEC 61850 data over TCP port 102 using TPKT/COTP transport. It is used by:
- **Substation automation** — protection relays, circuit breakers, transformers
- **Power grid SCADA** — supervisory control and data acquisition
- **Energy management systems** — generation and distribution control
- **IEC 61850 GOOSE** — when tunneled over MMS for wide-area protection

The plugin parses:
- TPKT headers (version, length)
- COTP PDU types (CR, CC, DT, DR, DC)
- MMS PDU types (Confirmed-Request/Response, Unconfirmed, Initiate, Conclude)
- MMS services (Read, Write, GetNameList, GetVariableAccessAttributes, etc.)
- Invoke IDs for request/response correlation
- MMS domain names (IEC 61850 Logical Devices)
- Variable names (IEC 61850 object paths: LDName/LNName$FC$DOName$DAName)
- S7comm discrimination (rejects S7comm on same port)

## EVE JSON Output

```json
{
  "timestamp": "2026-04-25T10:00:00.000000+0000",
  "event_type": "iec61850",
  "src_ip": "10.0.10.1",
  "dest_ip": "10.0.10.100",
  "src_port": 49152,
  "dest_port": 102,
  "proto": "TCP",
  "iec61850": {
    "pdu_type": "confirmed-request",
    "service": "read",
    "mms_domain": "LD0",
    "variable_name": "XCBR1$ST$Pos$stVal",
    "iec61850_path": "LD0/XCBR1$ST$Pos$stVal",
    "confirmed": true,
    "invoke_id": 1
  }
}
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
├── iec61850.rs    # Pure Rust TPKT/COTP/MMS wire protocol parser
├── state.rs       # Per-flow state and transaction management
└── logger.rs      # EVE JSON generation

plugin.c           # Suricata plugin entry point (SCPluginRegister)
applayer.c         # App-layer registration and callback routing
iec61850-plugin.h  # C header for plugin metadata
Makefile           # Build orchestration
```

## Security Use Cases

### Substation Monitoring
- Detect unauthorized MMS connections to protection relays
- Alert on Write operations to circuit breaker controls (XCBR)
- Monitor for unexpected GetNameList reconnaissance
- Track MMS session initiation patterns

### OT/ICS Security
- Detect lateral movement via IEC 61850 protocol
- Alert on access to safety-critical data objects
- Monitor for protocol anomalies (malformed BER encoding)
- Discriminate MMS from S7comm on shared port 102

### Compliance
- Audit all MMS Read/Write operations for NERC CIP
- Track access to critical infrastructure data points
- Log IEC 61850 object access patterns

## References

- [IEC 61850-8-1](https://webstore.iec.ch/publication/6021) Communication mapping to MMS
- [ISO 9506](https://www.iso.org/standard/37079.html) Manufacturing Message Specification
- [RFC 1006](https://tools.ietf.org/html/rfc1006) ISO Transport over TCP (TPKT)

## License

GPL-2.0-only (matching Suricata's license)
