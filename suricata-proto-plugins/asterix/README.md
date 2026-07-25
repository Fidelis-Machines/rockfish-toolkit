# Suricata ASTERIX Parser Plugin

Application-layer parser plugin for Suricata that decodes ASTERIX (All-purpose STructured EUROCONTROL Surveillance Information EXchange) binary protocol used for air traffic surveillance data.

## What It Parses

ASTERIX is the standard protocol for exchanging surveillance data in air traffic management (ATM) systems. It is used by:
- **Primary/Secondary radar** — monoradar target reports (CAT 001, 048)
- **ADS-B receivers** — automatic dependent surveillance (CAT 021)
- **Multilateration systems** — wide-area multilateration (CAT 020)
- **System track processors** — fused track data (CAT 062)
- **Sensor status** — radar health monitoring (CAT 034, 063)

The plugin parses:
- Data block headers (category, length)
- FSPEC (Field Specification) bitmasks
- CAT 048 fields: position (rho/theta), Mode-3/A squawk, Mode-C altitude, track number, time of day, ICAO address, callsign
- CAT 021 fields: ICAO address, lat/lon, geometric altitude, emitter category, callsign, track number
- Multiple data blocks per datagram

## EVE JSON Output

```json
{
  "timestamp": "2026-04-25T10:00:00.000000+0000",
  "event_type": "asterix",
  "src_ip": "10.0.5.1",
  "dest_ip": "10.0.5.100",
  "src_port": 8600,
  "dest_port": 8601,
  "proto": "UDP",
  "asterix": {
    "category": 48,
    "category_name": "Monoradar Target Reports (Enhanced)",
    "record_count": 1,
    "track_number": 1234,
    "icao_address": "A1B2C3",
    "callsign": "UAL123",
    "squawk_code": "7700",
    "altitude": 35000,
    "time_of_day": 43200.5
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
├── asterix.rs   # Pure Rust ASTERIX wire protocol parser
├── state.rs     # Per-flow state and transaction management
└── logger.rs    # EVE JSON generation

plugin.c         # Suricata plugin entry point (SCPluginRegister)
applayer.c       # App-layer registration and callback routing
asterix-plugin.h # C header for plugin metadata
Makefile         # Build orchestration
```

## Security Use Cases

### Air Traffic Monitoring
- Detect unauthorized ADS-B transmissions
- Monitor for squawk code anomalies (7500/7600/7700)
- Track unusual flight patterns via position data
- Alert on new ICAO addresses in controlled airspace

### Critical Infrastructure
- Monitor radar system health via CAT 034/063
- Detect data injection attacks on surveillance feeds
- Audit ATM system communication patterns

## License

GPL-2.0-only (matching Suricata's license)
