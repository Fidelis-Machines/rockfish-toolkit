# Suricata BACnet Parser Plugin

Application-layer parser plugin for Suricata that decodes the BACnet/IP (Building Automation and Control Networks) protocol used in building management systems (BMS) and industrial HVAC control.

## What It Parses

BACnet is the ASHRAE/ISO standard protocol for building automation, used by:
- **Johnson Controls** Metasys
- **Honeywell** Niagara Framework
- **Siemens** Desigo CC
- **Schneider Electric** EcoStruxure Building
- **Tridium** Niagara 4
- Various HVAC controllers, fire systems, and access control

The plugin parses:
- BVLC header (type, function, length)
- BVLC functions: Original-Unicast-NPDU, Original-Broadcast-NPDU, Forwarded-NPDU
- NPDU header (version, control, routing information)
- APDU types: Confirmed-REQ, Unconfirmed-REQ, Simple-ACK, Complex-ACK, Error, Reject, Abort
- BACnet services: ReadProperty, WriteProperty, SubscribeCOV, WhoIs, IAm, ReadPropertyMultiple
- Object types: Analog-Input, Analog-Output, Analog-Value, Binary-Input, Binary-Output, Device
- Object identifiers and property IDs

## EVE JSON Output

```json
{
  "timestamp": "2026-04-25T10:00:00.000000+0000",
  "event_type": "bacnet",
  "src_ip": "10.0.4.100",
  "dest_ip": "10.0.4.255",
  "src_port": 47808,
  "dest_port": 47808,
  "proto": "UDP",
  "bacnet": {
    "bvlc_function": "Original-Unicast-NPDU",
    "apdu_type": "Confirmed-REQ",
    "service_choice": "ReadProperty",
    "object_type": "Analog-Input",
    "object_instance": 1,
    "property_id": 85,
    "invoke_id": 7,
    "priority": 0
  }
}
```

## Suricata Rules

Example detection rules using the BACnet parser:

```
# Alert on BACnet Who-Is broadcast (device discovery)
alert udp any any -> any 47808 (msg:"BACnet Who-Is Broadcast"; app-layer-protocol:bacnet; content:"Who-Is"; sid:7000001; rev:1;)

# Alert on BACnet WriteProperty (control point modification)
alert udp any any -> any 47808 (msg:"BACnet WriteProperty"; app-layer-protocol:bacnet; content:"WriteProperty"; sid:7000002; rev:1;)

# Alert on BACnet ReinitializeDevice (device restart command)
alert udp any any -> any 47808 (msg:"BACnet ReinitializeDevice"; app-layer-protocol:bacnet; content:"ReinitializeDevice"; sid:7000003; rev:1;)

# Alert on BACnet DeviceCommunicationControl
alert udp any any -> any 47808 (msg:"BACnet DeviceCommunicationControl"; app-layer-protocol:bacnet; content:"DeviceCommunicationControl"; sid:7000004; rev:1;)
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

This copies `rockfish-bacnet-parser.so` to `/usr/lib/suricata/plugins/`.

### Configure Suricata

Add to `suricata.yaml`:

```yaml
plugins:
  - /usr/lib/suricata/plugins/rockfish-bacnet-parser.so

app-layer:
  protocols:
    bacnet:
      enabled: yes
```

## Architecture

```
src/
├── lib.rs       # Suricata FFI bridge (C-extern callbacks)
├── bacnet.rs    # Pure Rust BACnet wire protocol parser
├── state.rs     # Per-flow state and transaction management
└── logger.rs    # EVE JSON generation

plugin.c         # Suricata plugin entry point (SCPluginRegister)
applayer.c       # App-layer registration and callback routing
bacnet-plugin.h  # C header for plugin metadata
Makefile         # Build orchestration
```

## Security Use Cases

### Building Automation Security
- Detect unauthorized BACnet device discovery (Who-Is scans)
- Alert on WriteProperty to safety-critical setpoints (HVAC, fire suppression)
- Monitor for ReinitializeDevice commands (potential sabotage)
- Track DeviceCommunicationControl (disabling devices)

### OT/ICS Monitoring
- Inventory all BACnet devices via I-Am tracking
- Detect unauthorized controllers on the BACnet network
- Monitor for abnormal ReadProperty patterns (reconnaissance)
- Alert on changes to Binary-Output objects (physical actuators)

### Compliance
- Audit all write operations to controlled objects
- Verify network segmentation (BACnet traffic containment)
- Track device communication patterns for baseline

## References

- [ASHRAE Standard 135 — BACnet](https://www.ashrae.org/technical-resources/standards-and-guidelines/read-only-versions-of-ashrae-standards)
- [BACnet International](https://www.bacnetinternational.org/)
- [Suricata App-Layer Template](https://github.com/OISF/suricata/tree/master/rust/src/applayertemplate)

## License

GPL-2.0-only (matching Suricata's license)
