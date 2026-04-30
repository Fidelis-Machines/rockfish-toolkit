# Suricata CoAP Parser Plugin

Application-layer parser plugin for Suricata that decodes CoAP (Constrained Application Protocol, RFC 7252) over UDP ports 5683 (plaintext) and 5684 (DTLS).

## What It Parses

CoAP is a lightweight RESTful protocol designed for constrained IoT devices and networks. It is used by:
- **IoT devices** (sensors, actuators, smart home devices)
- **LwM2M** (Lightweight M2M device management)
- **Industrial IoT** gateways and edge devices
- **Thread/Matter** smart home protocols

The plugin parses:
- CoAP headers (version, type, code, message ID, token)
- Request methods (GET, POST, PUT, DELETE, FETCH, PATCH)
- Response codes (2.01 Created, 2.05 Content, 4.04 NotFound, 5.00 InternalServerError, etc.)
- Options (Uri-Path, Uri-Host, Uri-Query, Content-Format, Block1/Block2, Observe, etc.)
- Payload with content format detection
- Block-wise transfer tracking

## EVE JSON Output

```json
{
  "timestamp": "2026-04-25T10:00:00.000000+0000",
  "event_type": "coap",
  "src_ip": "10.0.4.100",
  "dest_ip": "10.0.4.200",
  "src_port": 49152,
  "dest_port": 5683,
  "proto": "UDP",
  "coap": {
    "type": "CON",
    "code_class": 0,
    "code_detail": 1,
    "method": "GET",
    "message_id": 1,
    "token": "aabb",
    "uri_path": "/sensor/temperature",
    "content_format": "application/json",
    "payload_size": 42,
    "options": ["Uri-Path", "Uri-Path", "Accept"]
  }
}
```

## Suricata Rules

```
# Alert on CoAP PUT/POST to actuator endpoints
alert udp any any -> any 5683 (msg:"CoAP Write to actuator"; app-layer-protocol:coap; content:"actuator"; sid:7000001; rev:1;)

# Alert on CoAP DELETE requests
alert udp any any -> any 5683 (msg:"CoAP DELETE request"; app-layer-protocol:coap; coap.code_class:0; coap.code_detail:4; sid:7000002; rev:1;)

# Alert on CoAP server errors
alert udp any 5683 -> any any (msg:"CoAP Server Error"; app-layer-protocol:coap; coap.code_class:5; sid:7000003; rev:1;)
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
├── coap.rs      # Pure Rust CoAP wire protocol parser
├── state.rs     # Per-flow state and transaction management
└── logger.rs    # EVE JSON generation

plugin.c         # Suricata plugin entry point (SCPluginRegister)
applayer.c       # App-layer registration and callback routing
coap-plugin.h    # C header for plugin metadata
Makefile         # Build orchestration
```

## License

GPL-2.0-only (matching Suricata's license)
