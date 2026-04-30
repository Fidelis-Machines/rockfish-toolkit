# Suricata EtherNet/IP (CIP) Parser Plugin

Application-layer parser plugin for Suricata that decodes the EtherNet/IP encapsulation protocol and embedded Common Industrial Protocol (CIP) used in industrial automation and SCADA systems.

## What It Parses

EtherNet/IP is the standard industrial Ethernet protocol used by:
- **Allen-Bradley/Rockwell** ControlLogix, CompactLogix PLCs
- **Omron** NX/NJ series controllers
- **Schneider Electric** Modicon M580
- **ABB** AC500 series
- Various HMIs, drives, and I/O modules

The plugin parses:
- Encapsulation header (command, length, session handle, status, sender context, options)
- Commands: RegisterSession, UnregisterSession, ListIdentity, ListServices, SendRRData, SendUnitData
- CIP layer: service code, class ID, instance ID, attribute ID
- CIP services: Get_Attribute_All, Get_Attribute_Single, Read_Tag, Write_Tag, Forward_Open, Forward_Close
- Identity items from ListIdentity responses (vendor, product name, serial number)

## EVE JSON Output

```json
{
  "timestamp": "2026-04-25T10:00:00.000000+0000",
  "event_type": "enip",
  "src_ip": "10.0.4.100",
  "dest_ip": "10.0.4.200",
  "src_port": 52301,
  "dest_port": 44818,
  "proto": "TCP",
  "enip": {
    "command": "SendRRData",
    "session_handle": 1,
    "cip_service": "Read_Tag",
    "cip_class": 2,
    "cip_instance": 1,
    "status": 0,
    "product_name": "1756-L71 Logix5571"
  }
}
```

## Suricata Rules

Example detection rules using the EtherNet/IP parser:

```
# Alert on EtherNet/IP session registration
alert tcp any any -> any 44818 (msg:"ENIP RegisterSession"; app-layer-protocol:enip; content:"\x65\x00"; offset:0; depth:2; sid:6000001; rev:1;)

# Alert on CIP Write_Tag operations
alert tcp any any -> any 44818 (msg:"ENIP CIP Write Tag"; app-layer-protocol:enip; content:"Write_Tag"; sid:6000002; rev:1;)

# Alert on CIP Forward_Open (connection establishment)
alert tcp any any -> any 44818 (msg:"ENIP CIP Forward Open"; app-layer-protocol:enip; content:"Forward_Open"; sid:6000003; rev:1;)

# Alert on EtherNet/IP ListIdentity (device discovery)
alert udp any any -> any 2222 (msg:"ENIP ListIdentity Scan"; app-layer-protocol:enip; content:"\x63\x00"; offset:0; depth:2; sid:6000004; rev:1;)
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

This copies `rockfish-enip-parser.so` to `/usr/lib/suricata/plugins/`.

### Configure Suricata

Add to `suricata.yaml`:

```yaml
plugins:
  - /usr/lib/suricata/plugins/rockfish-enip-parser.so

app-layer:
  protocols:
    enip:
      enabled: yes
```

## Architecture

```
src/
├── lib.rs       # Suricata FFI bridge (C-extern callbacks)
├── enip.rs      # Pure Rust EtherNet/IP wire protocol parser
├── state.rs     # Per-flow state and transaction management
└── logger.rs    # EVE JSON generation

plugin.c         # Suricata plugin entry point (SCPluginRegister)
applayer.c       # App-layer registration and callback routing
enip-plugin.h    # C header for plugin metadata
Makefile         # Build orchestration
```

## Security Use Cases

### OT/ICS Monitoring
- Detect unauthorized CIP Write_Tag operations to safety-critical tags
- Alert on Forward_Open connections from unexpected sources
- Monitor ListIdentity scans for device reconnaissance
- Track session establishment patterns for anomaly detection

### Compliance
- Audit all PLC programming operations (Read/Write tags)
- Verify network segmentation (no ENIP traffic crossing zones)
- Monitor for firmware update operations

## References

- [ODVA EtherNet/IP Specification](https://www.odva.org/technology-standards/key-technologies/ethernet-ip/)
- [CIP Specification (Common Industrial Protocol)](https://www.odva.org/technology-standards/key-technologies/common-industrial-protocol-cip/)
- [Suricata App-Layer Template](https://github.com/OISF/suricata/tree/master/rust/src/applayertemplate)

## License

GPL-2.0-only (matching Suricata's license)
