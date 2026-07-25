# Suricata LwM2M Parser Plugin

Application-layer parser plugin for Suricata that decodes LwM2M (Lightweight M2M) messages carried over CoAP (Constrained Application Protocol).

## What It Parses

LwM2M is a device management protocol for IoT devices, running over CoAP on UDP ports 5683 (plain) and 5684 (DTLS). It is used by:
- **IoT device management** — firmware updates, configuration, monitoring
- **Smart metering** — utility meter reading and control
- **Industrial sensors** — edge device lifecycle management
- **LPWAN devices** — NB-IoT, LTE-M device management

The plugin parses:
- CoAP message headers (version, type, code, message ID, token)
- LwM2M URI paths (object/instance/resource addressing)
- Registration operations (POST /rd with endpoint name, lifetime, version)
- Bootstrap operations (POST /bs)
- Device management operations (Read, Write, Execute, Create, Delete)
- Observe/Notify operations (CoAP Observe option)
- Payload format detection (TLV, JSON, CBOR, SenML)

## Well-Known LwM2M Objects

| Object ID | Name |
|-----------|------|
| 0 | Security |
| 1 | Server |
| 2 | Access Control |
| 3 | Device |
| 4 | Connectivity Monitoring |
| 5 | Firmware Update |
| 6 | Location |
| 7 | Connectivity Statistics |

## EVE JSON Output

```json
{
  "timestamp": "2026-04-25T10:00:00.000000+0000",
  "event_type": "lwm2m",
  "src_ip": "10.0.1.100",
  "dest_ip": "10.0.1.1",
  "src_port": 49152,
  "dest_port": 5683,
  "proto": "UDP",
  "lwm2m": {
    "operation": "Register",
    "endpoint_name": "my_sensor",
    "lifetime": 3600,
    "lwm2m_version": "1.1",
    "coap_type": "CON",
    "coap_code": "0.02",
    "uri_path": "/rd"
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
├── lib.rs       # Suricata FFI bridge (C-extern callbacks)
├── lwm2m.rs     # Pure Rust CoAP/LwM2M wire protocol parser
├── state.rs     # Per-flow state and transaction management
└── logger.rs    # EVE JSON generation

plugin.c         # Suricata plugin entry point (SCPluginRegister)
applayer.c       # App-layer registration and callback routing
lwm2m-plugin.h   # C header for plugin metadata
Makefile         # Build orchestration
```

## License

GPL-2.0-only (matching Suricata's license)
