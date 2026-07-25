# Suricata OPC UA Parser Plugin

Application-layer parser plugin for Suricata that decodes the OPC UA (Open Platform Communications Unified Architecture) binary protocol used in industrial automation and SCADA systems.

## What It Parses

OPC UA is the standard protocol for industrial automation communication, used by:
- **Siemens S7** PLCs (via OPC UA server)
- **Beckhoff TwinCAT** automation systems
- **Rockwell Automation** FactoryTalk
- **ABB Ability** platforms
- **Unified Automation** SDK-based applications

The plugin parses:
- Message headers (type: HEL/ACK/ERR/OPN/CLO/MSG, chunk type, size)
- Hello/Acknowledge handshake (endpoint URL, buffer sizes)
- Secure channel establishment (security policy, security mode)
- Service requests and responses (Read, Write, Browse, Call, Publish, CreateSession)
- Node IDs referenced in service calls
- Security modes (None, Sign, SignAndEncrypt)

## EVE JSON Output

```json
{
  "timestamp": "2026-04-25T10:00:00.000000+0000",
  "event_type": "opcua",
  "src_ip": "10.0.4.100",
  "dest_ip": "10.0.4.200",
  "src_port": 52301,
  "dest_port": 4840,
  "proto": "TCP",
  "opcua": {
    "message_type": "Message",
    "security_mode": "SignAndEncrypt",
    "security_policy": "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    "endpoint_url": "opc.tcp://plc01.factory:4840",
    "service_type": "Read",
    "node_ids": ["ns=0; i=631"],
    "status_code": 0,
    "secure_channel_id": 1,
    "sequence_number": 42,
    "request_id": 7
  }
}
```

## Suricata Rules

Example detection rules using the OPC UA parser:

```
# Alert on OPC UA traffic without encryption
alert tcp any any -> any 4840 (msg:"OPC UA Unencrypted Session"; app-layer-protocol:opcua; content:"None"; sid:5000001; rev:1;)

# Alert on OPC UA Write operations
alert tcp any any -> any 4840 (msg:"OPC UA Write Operation"; app-layer-protocol:opcua; content:"Write"; sid:5000002; rev:1;)

# Alert on new OPC UA connections
alert tcp any any -> any 4840 (msg:"OPC UA Hello"; app-layer-protocol:opcua; content:"HEL"; offset:0; depth:3; sid:5000003; rev:1;)

# Alert on OPC UA Browse (reconnaissance)
alert tcp any any -> any 4840 (msg:"OPC UA Browse - Possible Recon"; app-layer-protocol:opcua; content:"Browse"; sid:5000004; rev:1;)
```

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

This copies `rockfish-opcua-parser.so` to `/usr/lib/suricata/plugins/`.

### Configure Suricata

Add to `suricata.yaml`:

```yaml
plugins:
  - /usr/lib/suricata/plugins/rockfish-opcua-parser.so

app-layer:
  protocols:
    opcua:
      enabled: yes
```

## Architecture

```
src/
├── lib.rs       # Suricata FFI bridge (C-extern callbacks)
├── opcua.rs     # Pure Rust OPC UA wire protocol parser
├── state.rs     # Per-flow state and transaction management
└── logger.rs    # EVE JSON generation

plugin.c         # Suricata plugin entry point (SCPluginRegister)
applayer.c       # App-layer registration and callback routing
opcua-plugin.h   # C header for plugin metadata
Makefile         # Build orchestration
```

## Security Use Cases

### OT/ICS Monitoring
- Detect unauthorized OPC UA clients connecting to PLCs
- Alert on Write operations to critical control variables
- Monitor for unencrypted OPC UA sessions in production
- Detect Browse operations indicating reconnaissance

### Compliance
- Verify OPC UA security policy enforcement (encryption required)
- Audit all Read/Write operations to safety-critical nodes
- Track session establishment and teardown patterns

## References

- [OPC UA Specification Part 6 — Mappings](https://opcfoundation.org/developer-tools/specifications-opc-ua)
- [Suricata App-Layer Template](https://github.com/OISF/suricata/tree/master/rust/src/applayertemplate)

## License

GPL-2.0-only (matching Suricata's license)
