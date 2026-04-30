# Suricata PROFINET Parser Plugin

Application-layer parser plugin for Suricata that decodes PROFINET DCP (Discovery and Configuration Protocol) over UDP port 34964.

## What It Parses

PROFINET is the industrial Ethernet standard from Siemens/PROFIBUS International, used in factory automation, process control, and motion control systems.

This plugin focuses on the DCP discovery protocol over UDP, which Suricata can process at the app-layer:
- DCP frame headers (Frame ID, Service ID, Service Type, XID)
- DCP blocks (Name-of-Station, IP-Parameter, Device-ID, DHCP, etc.)
- Service types (Get, Set, Identify, Hello)

**NOTE:** Layer 2 PROFINET RT/IRT monitoring (EtherType 0x8892/0x8893) requires a separate Suricata ethertype decoder and is documented separately.

## Frame ID Ranges

| Range | Type |
|-------|------|
| 0x0000-0x7FFF | RT Class 3 Cyclic |
| 0x8000-0xBFFF | RT Class 1 Cyclic |
| 0xC000-0xFBFF | RT Class Acyclic |
| 0xFC00-0xFCFF | Alarm |
| 0xFE00-0xFEFF | DCP |
| 0xFF00-0xFFFF | Reserved |

## EVE JSON Output

```json
{
  "timestamp": "2026-04-25T10:00:00.000000+0000",
  "event_type": "profinet",
  "src_ip": "10.0.4.100",
  "dest_ip": "10.0.4.255",
  "src_port": 49152,
  "dest_port": 34964,
  "proto": "UDP",
  "profinet": {
    "frame_id": "0xfefe",
    "frame_type": "dcp",
    "service_id": "Identify",
    "service_type": "Request",
    "xid": 66,
    "station_name": "plc-station-1",
    "device_id": "002a:0401",
    "ip_address": "192.168.1.100",
    "blocks": [
      { "option": "Name-of-Station", "value": "plc-station-1" }
    ]
  }
}
```

## Suricata Rules

```
# Alert on PROFINET DCP Set operations
alert udp any any -> any 34964 (msg:"PROFINET DCP Set Operation"; app-layer-protocol:profinet; profinet.service_type:0x04; sid:6000001; rev:1;)

# Alert on PROFINET device discovery
alert udp any any -> any 34964 (msg:"PROFINET DCP Identify"; app-layer-protocol:profinet; profinet.service_type:0x05; sid:6000002; rev:1;)
```

## Building

```bash
SURICATA_SRC=/path/to/suricata make
make test
```

## Architecture

```
src/
├── lib.rs       # Suricata FFI bridge (C-extern callbacks)
├── profinet.rs  # Pure Rust PROFINET DCP protocol parser
├── state.rs     # Per-flow state and transaction management
└── logger.rs    # EVE JSON generation

plugin.c         # Suricata plugin entry point (SCPluginRegister)
applayer.c       # App-layer registration and callback routing
profinet-plugin.h # C header for plugin metadata
Makefile         # Build orchestration
```

## License

GPL-2.0-only (matching Suricata's license)
