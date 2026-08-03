<p align="center">
  <a href="https://rockfishndr.com" title="Rockfish NDR — learn more"><img src="https://rockfishndr.com/rockfish-logo.png" alt="Rockfish NDR" width="320"></a>
</p>

<h2 align="center">Rockfish Deployment Toolkit</h2>

<p align="center"><em>The Suricata plugins &amp; deployment kit that integrate Suricata with Rockfish NDR.</em></p>

<p align="center">
  <a href="https://demo.rockfishndr.com"><strong>Live Demo</strong></a> &middot;
  <a href="https://docs.rockfishndr.com/">Documentation</a> &middot;
  <a href="https://github.com/Fidelis-Machines/rockfish-toolkit/issues">Issues</a>
</p>

## Contents

| Stage | Functions |
|---|---|
| **Deploy** ⭐ | [Quick install](#quick-install) &middot; [`install/install.sh` (installer + verify)](install/) &middot; [Run RockfishNDR in Docker](#run-rockfish-in-docker) |
| **Capture** | [FMADIO ring **Suricata capture plugin**](#suricata-capture-plugin) |
| **Decode** | [OT / IIoT protocol **Suricata plugins**](#suricata-protocol-plugins-industrial-protocols) |
| **Telemetry** | [`UDP/TCP metrics` **Suricata plugin**](#transport_signals--network-signal-metrics) |
| **ETA** | [Encrypted Traffic Analysis (ETA) **Suricata plugin**](#payload_entropy--encrypted-traffic-analysis) |
| **PQC** | [Post-quantum cryptography (PQC) **Suricata plugin**](#tls_pqc--post-quantum-cryptography-pqc-compliance) ([NIST IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf)) |
| **Respond** *(coming soon)* | [Response pipeline integrations](integrations/) &middot; [MQTT](integrations/mqtt/) &middot; [Kafka](integrations/kafka/) &middot; [Webhook](integrations/webhook/) |

**Reference:** [Build scripts](#build-scripts) &middot; [Requirements](#requirements) &middot; [Building](#building) &middot; [Repository layout](#repository-layout)

## Description

Rockfish Toolkit is the **Suricata deployment kit for [Rockfish NDR](https://rockfishndr.com)** — the **Suricata plugins** and packaging that integrate Suricata with the Rockfish NDR engine and stand up a sensor in production. Everything here extends Suricata: a line-rate **capture plugin**, **protocol-decode plugins** for IIoT/OT, and **telemetry plugins** for per-flow signals, encrypted-traffic analytics (ETA), and post-quantum (PQC) compliance — all emitting through Suricata's `eve-log` — plus a Docker/APT deployment recipe. The NDR detection engine ships separately; the toolkit is the open **Suricata-integration layer** around it, organized by stage:

| Stage | What it does | In the toolkit |
|---|---|---|
| **Capture** | Get packets in at line rate | FMADIO shared-memory ring **Suricata capture plugin** |
| **Decode** | Parse IIoT/OT protocols Suricata doesn't ship | **Suricata protocol plugins:** S7comm, OPC UA, BACnet, IEC 61850/104, PROFINET, EtherCAT, ENIP, … |
| **Telemetry** | Compute the per-flow signals the detection engines consume | **Suricata plugins:** transport signals (odometry), Encrypted Traffic Analytics / entropy (ETA), post-quantum cryptography (PQC) compliance |
| **Deploy** | Run the published release without a source build | Docker recipe that pulls `rockfish` from the APT repo |
| **Respond** *(coming soon)* | Wire detections into your response & automation stack | Integration hooks / recipes for MQTT, Kafka, webhooks, SOAR |

It grows with each phase of Fidelis Machines' research in ROS / OT / IoT security.

> **Learn more about Rockfish NDR** — the air-gap-native Network Detection &amp; Response solution this toolkit integrates with: <https://rockfishndr.com>


## Quick install

Install the Rockfish NDR engine (the detection engine this toolkit feeds) with
one command. The installer auto-detects your platform — APT on Debian/Ubuntu,
Docker elsewhere:

```bash
curl -fsSL https://docs.rockfishndr.com/install.sh | bash
```

**Verify** an install at any time — read-only diagnostics that exit non-zero if
anything is missing:

```bash
curl -fsSL https://docs.rockfishndr.com/install.sh | bash -s -- verify
```

Options:

```bash
# Pin a specific version
ROCKFISH_VERSION=2026.07.6 curl -fsSL https://docs.rockfishndr.com/install.sh | bash

# Force a method (apt or docker)
ROCKFISH_METHOD=apt    curl -fsSL https://docs.rockfishndr.com/install.sh | bash
ROCKFISH_METHOD=docker curl -fsSL https://docs.rockfishndr.com/install.sh | bash
```

The authoritative script lives in this repo at [`install/install.sh`](install/install.sh)
(the docs URL above serves a synced copy) — read it before piping to a shell,
or run it after cloning. Full write-up: [`install/README.md`](install/README.md).
It installs only the **engine**; build and load the **Suricata plugins** below
to feed it. See the
[installation docs](https://docs.rockfishndr.com/getting-started/installation.html).

## Get the code

```bash
git clone https://github.com/Fidelis-Machines/rockfish-toolkit.git
cd rockfish-toolkit
```

Browse the source on GitHub: <https://github.com/Fidelis-Machines/rockfish-toolkit>

## Components

### Suricata capture plugin

| Plugin | Description |
|---|---|
| [`suricata-plugin-fmadio-ring/`](suricata-plugin-fmadio-ring/) | Zero-copy packet capture from FMADIO shared-memory ring buffers (`/opt/fmadio/queue/lxc_ring*`). One worker thread per ring. |

### Suricata telemetry plugins

| Plugin | Emits | Description |
|---|---|---|
| [`suricata-proto-plugins/transport_signals/`](suricata-proto-plugins/transport_signals/) | `tcp_signal`, `udp_signal` | Per-flow TCP handshake RTT, retransmits, zero-windows, window stats; UDP request/response RTT and inter-arrival time variance. Downstream consumers derive odometry from these. |
| [`suricata-proto-plugins/payload_entropy/`](suricata-proto-plugins/payload_entropy/) | `payload_entropy` | Per-flow Shannon entropy and SPLT (Sequence of Packet Lengths and Times). PCR is derived downstream from `transport_signals` byte totals. |
| [`suricata-proto-plugins/tls_pqc/`](suricata-proto-plugins/tls_pqc/) | `pqc` | Per-handshake post-quantum key-exchange classification — the ClientHello supported groups and the TLS 1.3 ServerHello chosen group, plus a NIST IR 8547 compliance verdict (`exposure_class`). |

### Suricata protocol plugins (industrial protocols)

Application-layer parsers that decode binary protocols not covered by
Suricata's built-ins. Each emits its own EVE event type.

| Plugin | Protocol | Default port |
|---|---|---|
| [`asterix/`](suricata-proto-plugins/asterix/) | EUROCONTROL ASTERIX (radar / ADS-B surveillance) | UDP |
| [`bacnet/`](suricata-proto-plugins/bacnet/) | BACnet (building automation) | UDP 47808 |
| [`canopen/`](suricata-proto-plugins/canopen/) | CANopen (CAN-over-UDP) | UDP |
| [`coap/`](suricata-proto-plugins/coap/) | CoAP (constrained IoT) | UDP 5683 |
| [`enip/`](suricata-proto-plugins/enip/) | EtherNet/IP (CIP) | TCP/UDP 44818 / 2222 |
| [`ethercat/`](suricata-proto-plugins/ethercat/) | EtherCAT (industrial fieldbus) | L2 / UDP |
| [`iec104/`](suricata-proto-plugins/iec104/) | IEC 60870-5-104 (power/SCADA) | TCP 2404 |
| [`iec61850/`](suricata-proto-plugins/iec61850/) | IEC 61850 MMS (substation automation) | TCP 102 |
| [`lwm2m/`](suricata-proto-plugins/lwm2m/) | LwM2M (CoAP-based device mgmt) | UDP 5683 |
| [`opcua/`](suricata-proto-plugins/opcua/) | OPC UA (industrial telemetry) | TCP 4840 |
| [`profinet/`](suricata-proto-plugins/profinet/) | PROFINET DCP | UDP 34964 |
| [`s7comm/`](suricata-proto-plugins/s7comm/) | Siemens S7comm | TCP 102 |

> Suricata parses `enip`, `modbus`, `dnp3`, and `mqtt` natively — those EVE
> events feed Rockfish directly with no plugin needed. The `enip/` plugin
> here adds extended decoding beyond the built-in.

### Build scripts

All scripts live in [`scripts/`](scripts/) and must be run from inside the
`rockfish-toolkit` checkout (enforced by `_common.sh`).

| Script | Builds |
|---|---|
| [`scripts/build-plugins.sh`](scripts/build-plugins.sh) | All IIoT/OT protocol parsers (or a named subset). |
| [`scripts/build-signals.sh`](scripts/build-signals.sh) | `transport_signals` only. |
| [`scripts/build-entropy.sh`](scripts/build-entropy.sh) | `payload_entropy` only. |
| [`scripts/build-pqc.sh`](scripts/build-pqc.sh) | `tls_pqc` only. |

The FMADIO ring plugin is built directly via its own `Makefile` (see
[its README](suricata-plugin-fmadio-ring/README.md)).

### Run Rockfish in Docker

[`docker/`](docker/) has a `Dockerfile` that installs the published `rockfish`
release from the APT repo and runs the CLI in a container — no source build.
See [docker/README.md](docker/README.md).

```bash
cd docker && docker build -t rockfish .
docker run --rm rockfish --version
```

### Response pipelines & output integrations — *coming soon*

Recipes and reference hooks for routing Rockfish NDR detections into your
response and automation stack, in [`integrations/`](integrations/) — one
subdirectory per function. Rockfish already **publishes** to MQTT, Kafka, and
webhooks at the appropriate license tiers; these recipes sit on top of those
outputs:

| Directory | Integration | Rockfish output | Status |
|---|---|---|---|
| [`integrations/mqtt/`](integrations/mqtt/) | MQTT → OT/SCADA broker | MQTT (Enterprise) | planned |
| [`integrations/kafka/`](integrations/kafka/) | Kafka topic bridge → SIEM / data lake | Kafka (Enterprise) | planned |
| [`integrations/webhook/`](integrations/webhook/) | Webhook → SOAR / ticketing / chat | Webhook (Professional) | planned |

> Want a specific integration prioritized? [Open an issue](https://github.com/Fidelis-Machines/rockfish-toolkit/issues).

## Suricata telemetry plugins in detail

The two telemetry plugins are the analytics workhorses of the toolkit —
they don't decode application protocols, they compute per-flow signals
that downstream detection engines (HBOS, SIGMA) consume.

### `transport_signals` — Network signal metrics

A Suricata plugin that emits **`tcp_signal`** and **`udp_signal`**
events alongside Suricata's normal flow records. It tracks the per-flow
signals you'd normally need a separate APM agent for — handshake
latency, retransmits, request/response RTT, jitter — without touching
the application stack. Downstream consumers turn these into odometry
(relative, incremental measurements anchored to the flow's first
observation) by joining on `flow_id`.

**TCP metrics** (emitted as `tcp_signal` events, one per flow):

| Field | Meaning |
|---|---|
| `start_us` / `end_us` / `duration_us` | Flow timing window (µs since epoch / duration) |
| `handshake_rtt_us` | SYN-to-SYN/ACK time on the three-way handshake |
| `first_byte_toserver_us` / `_toclient_us` | Time-to-first-payload-byte per direction, relative to flow start |
| `data_toserver` / `_toclient` | Full-flow payload byte totals per direction (downstream derives PCR from these) |
| `retransmits_toserver` / `_toclient` | Detected duplicate-sequence counts per direction |
| `out_of_order_toserver` / `_toclient` | Forward-jump (gap) counts per direction |
| `zero_window_toserver` / `_toclient` | Receive-window-exhaustion events per direction |
| `rst_count` / `fin_count` | Aggregate RST and FIN flag counts |
| `avg_window_toserver` / `min_…` / `max_…` (and `_toclient` triplet) | Receive-window stats per direction |
| `close_reason` | `fin`, `rst`, or `timeout` |

**UDP metrics** (emitted as `udp_signal` events):

| Field | Meaning |
|---|---|
| `start_us` / `end_us` / `duration_us` | Flow timing window (µs since epoch / duration) |
| `first_byte_toserver_us` / `_toclient_us` | Time-to-first-byte per direction, relative to flow start |
| `data_toserver` / `_toclient` | Full-flow payload byte totals per direction |
| `rtt_count` / `rtt_min_us` / `rtt_max_us` / `rtt_avg_us` / `rtt_stddev_us` | Paired request/response RTT (within a configurable pairing window) |
| `iat_avg_toserver_us` / `_toclient_us` | Mean inter-arrival time per direction |
| `iat_stddev_toserver_us` / `_toclient_us` | Inter-arrival time variance per direction |

**Configuration** (`rockfish-transport-signals:` block in `suricata.yaml`):

| Key | Default | Description |
|---|---|---|
| `enabled` | `yes` | Master toggle |
| `tcp` | `yes` | Track TCP flows |
| `udp` | `yes` | Track UDP flows |
| `sample-rate` | `1` | Emit every Nth flow (1 = every flow) |
| `max-flows` | `100000` | Memory cap on the in-flight flow table |

**What it catches** — congested links, brownouts before users notice
them (handshake-latency drift), failing peers (rising retransmits),
capacity issues (zero-window saturation), zombie connections (high RST
rate), and UDP-app degradation (request/response RTT drift, IAT
variance spikes). Surfaces in the Rockfish NDR **Performance** report
page and SLA dashboards.

### `payload_entropy` — Encrypted Traffic Analysis

A Suricata plugin emitting **`payload_entropy`** events. Implements
a feature set similar to Cisco's ETA (Encrypted Traffic Analytics), letting you
fingerprint traffic that's already inside TLS/QUIC without breaking
encryption — finds C2 beacons, exfiltration tunnels, and custom-protocol
covert channels by their **shape**, not their content.

Metrics are computed during a capped sample window (default first 8 KB
per direction) so the cost stays bounded on long-lived flows.

**Per-direction Shannon entropy** — `entropy_toserver`,
`entropy_toclient` (bits/byte). Properly encrypted traffic sits at ~7.9;
structured / plaintext payloads fall below 6; tunneled binary embedded
inside an encrypted-looking wrapper is recognizable here.

**PCR (Producer / Consumer Ratio)** — derived downstream from the
`transport_signals` plugin's `data_toserver` / `data_toclient` totals,
not emitted by `payload_entropy` itself. `pcr ∈ [0..1] = data_toserver /
(data_toserver + data_toclient)`. Conversation shape in one number:
- `pcr ≈ 0.05` → client-receives (download, browsing)
- `pcr ≈ 0.50` → symmetric (interactive)
- `pcr ≈ 0.85+` → client-sends (upload, **exfil candidate**)

Computing PCR downstream lets it cover the **full flow** (rather than
just the entropy plugin's sample window), so the ratio is accurate for
long-lived bulk transfers too.

**SPLT — Sequence of Packet Lengths and Times** in three forms:
- `splt_lengths` — `Vec<u16>` of raw payload lengths (first N packets)
- `splt_iats_us` — `Vec<u32>` of inter-arrival times in microseconds
- `splt` — letter-encoded summary string. Each packet becomes a letter
  where **case marks direction** (uppercase = toserver, lowercase =
  toclient) and the letter `A..K` / `a..k` is the log₂ size bucket
  from `<32 B` to `≥1024 B`. Easy to grep for patterns:
  - `AaAaAaAa` → regular small handshakes (likely beaconing)
  - `AaKKKKKK` → small request, bulk transfer
  - `KkKkKkKk` → balanced bulk

**Sample-window byte counts** — `bytes_sampled_toserver`,
`bytes_sampled_toclient` so consumers know how representative the
entropy reading is.

**Configuration** (`rockfish-payload-entropy:` block):

| Key | Default | Description |
|---|---|---|
| `enabled` | `yes` | Master toggle |
| `tcp` | `yes` | Sample TCP flows |
| `udp` | `yes` | Sample UDP flows |
| `sample-rate` | `1` | Emit every Nth flow |
| `max-bytes-per-direction` | `8192` | Bytes inspected per direction (memory bound) |
| `emit.entropy` | `yes` | Emit entropy fields |
| `emit.splt` | `yes` | Emit SPLT fields (heaviest payload — disable to shrink event size) |

**What it catches** — beaconing (regular SPLT pattern + `pcr ≈ 0.5`
over many short flows), exfiltration (high PCR + elevated entropy
outbound), tunneling (entropy mismatch with expected protocol — e.g.,
port 53 with `entropy_toserver = 7.8`), and C2 traffic that no signature
matches but whose SPLT shape is anomalous for the destination. Surfaces
in the Rockfish NDR **Encryption** report page: top encrypted talkers,
exfil candidates, beacons by SPLT, common-shape clusters, and
per-protocol entropy anomalies.

### `tls_pqc` — Post-quantum cryptography (PQC) compliance

Classifies the post-quantum posture of every TLS handshake, per
[NIST IR 8547] transition guidance, emitting one `pqc` EVE event per flow. It
surfaces two facts the stock Suricata TLS log drops: the ClientHello
**supported_groups** (extension 10) and the TLS 1.3 ServerHello **key_share**
(extension 51) — the group the server actually chose.

```json
{
  "event_type": "pqc",
  "pqc": {
    "tls_version": "TLS 1.3",
    "client_offered_pqc": true,
    "client_supported_groups": [4588, 29, 23, 24],
    "server_chosen_group": 4588,
    "server_chosen_group_name": "X25519MLKEM768",
    "server_chosen_pqc": true,
    "nist_compliant": true,
    "exposure_class": "compliant"
  }
}
```

`exposure_class` is one of `compliant` (server negotiated a PQ KEM),
`server_lagging` (client offered PQ, server chose classical — silent exposure),
`client_lagging` (client never offered PQ), `partial` (TLS 1.2 — no key_share to
inspect), or `unknown`. Recognized PQ codepoints include X25519MLKEM768 (4588)
and ML-KEM-512/1024 (4587/4589). Surfaces in the Rockfish NDR **TLS** report
page under "NIST PQC Compliance". See
[`suricata-proto-plugins/tls_pqc/README.md`](suricata-proto-plugins/tls_pqc/README.md)
for the full field reference.

[NIST IR 8547]: https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf

## Requirements

- Suricata 8.0+ (with plugin support enabled — `--enable-plugins`)
- Rust 1.70+ and Cargo
- GCC or Clang
- For the FMADIO ring plugin: access to `/opt/fmadio/queue/lxc_ring*`

## Building

Each plugin can be built standalone, or you can build them in batches
through the helper scripts.

### Build everything

```bash
# Protocol parsers (all of them)
./scripts/build-plugins.sh

# Telemetry plugins
./scripts/build-signals.sh
./scripts/build-entropy.sh
./scripts/build-pqc.sh

# FMADIO capture plugin
make -C suricata-plugin-fmadio-ring
```

### Build a subset

```bash
# Just OPC UA and S7comm
./scripts/build-plugins.sh opcua s7comm

# Run unit tests (no Suricata dependency)
./scripts/build-plugins.sh --test

# Clean
./scripts/build-plugins.sh --clean
```

### Build and install

```bash
# Protocol parsers → /opt/rockfish/plugins/  (override with PLUGIN_DIR_INSTALL)
./scripts/build-plugins.sh --install

# Telemetry plugins → /usr/lib/suricata/plugins/
./scripts/build-signals.sh --install
./scripts/build-entropy.sh --install

# FMADIO capture plugin → /opt/suricata/lib/  (override with PLUGIN_DIR)
sudo make -C suricata-plugin-fmadio-ring install
```

### Build options

| Variable | Default | Used by |
|---|---|---|
| `SURICATA_SRC` | `/development/suricata` | All scripts — path to a configured Suricata source tree. Falls back to a Rust-only static-lib build if Suricata isn't found. |
| `PLUGIN_DIR_INSTALL` | `/opt/rockfish/plugins` | `build-plugins.sh --install` |
| `PLUGIN_DIR` | `/opt/suricata/lib` | FMADIO ring `make install` |
| `DUCKDB_LIB_DIR` | `/usr/local/lib` | Set by `_common.sh` for plugins that link DuckDB. |

If `libsuricata-config` is on `PATH`, it's used to discover include paths
automatically and `SURICATA_SRC` is ignored.

## Configuring Suricata

All plugins follow the same wiring pattern: load the `.so` under
`plugins:`, then enable the corresponding event type or app-layer
protocol. Telemetry events flow through Suricata's normal eve-log
pipeline — no second socket, no second file.

### Example `suricata.yaml`

```yaml
# 1. Load the plugin shared objects
plugins:
  # Capture (FMADIO ring)
  - /opt/suricata/lib/fmadio-ring.so

  # Telemetry
  - /usr/lib/suricata/plugins/rockfish-transport-signals.so
  - /usr/lib/suricata/plugins/rockfish-payload-entropy.so

  # Protocol parsers
  - /opt/rockfish/plugins/rockfish-opcua-parser.so
  - /opt/rockfish/plugins/rockfish-s7comm-parser.so
  - /opt/rockfish/plugins/rockfish-bacnet-parser.so
  - /opt/rockfish/plugins/rockfish-asterix-parser.so
  # ... add others as needed

# 2. Enable parsers under app-layer
app-layer:
  protocols:
    opcua:    { enabled: yes }
    s7comm:   { enabled: yes }
    bacnet:   { enabled: yes }
    asterix:  { enabled: yes }

# 3. Enable telemetry event types in eve-log
outputs:
  - eve-log:
      enabled: yes
      filetype: unix_stream
      filename: /var/run/rockfish/rockfish.sock
      types:
        - alert
        - flow
        - dns
        - tls: { extended: yes }
        - http
        # Telemetry plugin events
        - tcp_signal
        - udp_signal
        - payload_entropy
        # Protocol parser events
        - opcua
        - s7comm
        - bacnet
        - asterix

# 4. Per-plugin tuning (all keys optional — defaults shown)
rockfish-transport-signals:
  enabled: yes
  tcp: yes
  udp: yes
  sample-rate: 1
  max-flows: 100000

rockfish-payload-entropy:
  enabled: yes
  tcp: yes
  udp: yes
  sample-rate: 1
  max-bytes-per-direction: 8192
  emit:
    entropy: yes
    splt: yes

# 5. FMADIO ring capture (one entry per ring = one worker thread)
fmadio-ring:
  - ring: /opt/fmadio/queue/lxc_ring0
  - ring: /opt/fmadio/queue/lxc_ring1
```

### Running Suricata with the FMADIO capture plugin

```bash
suricata --capture-plugin fmadio-ring \
         -c /etc/suricata/suricata.yaml
```

Per-ring counters are exposed under `capture.fmadio_ringN.{packets,bytes,drops}`
and visible via `suricatasc -c "dump-counters" | grep fmadio`.

See each plugin's own README for the full set of tuning knobs, output
schemas, and example queries.

## Repository layout

```
rockfish-toolkit/
├── install/                       # Deploy: one-line engine installer + verify
│   ├── install.sh                 #   authoritative installer (install | verify)
│   └── README.md                  #   installer documentation
├── docker/                        # Deploy: Dockerfile + README to run the rockfish CLI
├── integrations/                  # Respond: response-pipeline recipes (coming soon)
│   ├── mqtt/                       #   MQTT → OT/SCADA broker
│   ├── kafka/                      #   Kafka → SIEM / data lake
│   └── webhook/                    #   Webhook → SOAR / ticketing / chat
├── scripts/                       # Build helpers (build-plugins.sh, etc.)
├── suricata-plugin-fmadio-ring/   # Capture: FMADIO ring-buffer capture plugin
└── suricata-proto-plugins/        # Decode + Telemetry
    ├── common/                    # Shared headers
    ├── transport_signals/         # tcp_signal / udp_signal telemetry
    ├── payload_entropy/           # entropy / SPLT telemetry
    ├── tls_pqc/                   # post-quantum TLS compliance (pqc)
    ├── asterix/  bacnet/  canopen/  coap/  enip/  ethercat/
    ├── iec104/   iec61850/  lwm2m/  opcua/  profinet/  s7comm/
```

## License

GPL-2.0-only (matching Suricata).
# rockfish-toolkit
