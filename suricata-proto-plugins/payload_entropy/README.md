# Rockfish Suricata Payload Entropy Plugin

Three configurable signals per flow, all over the same sampled packet
window. Each signal is independently enable/disable-able from
`suricata.yaml`; by default all three are emitted when the plugin is on.

| Signal | Fields |
|---|---|
| **Entropy** | `entropy_toserver`, `entropy_toclient`, `bytes_sampled_to{server,client}` |
| **PCR** (producer/consumer ratio) | `pcr` |
| **SPLT** (Sequence of Packet Lengths and Times) | `splt`, `splt_lengths`, `splt_iats_us` |

All three operate on **application payload** bytes (post-TCP/UDP/IP
headers). Emitted as `payload_entropy` events through Suricata's normal
eve-log pipeline.

## Build

```sh
./scripts/build-entropy.sh                    # build only
./scripts/build-entropy.sh --install          # build + install
./scripts/build-entropy.sh --test             # cargo test
```

## Configuration

```yaml
plugins:
  - /usr/lib/suricata/plugins/rockfish-payload-entropy.so

outputs:
  - eve-log:
      filetype: unix_stream
      filename: /var/run/rockfish/rockfish.sock
      types:
        - alert
        - flow
        - tcp_perf
        - udp_perf
        - payload_entropy        # <-- enable this plugin's output

rockfish-payload-entropy:
  enabled: yes
  tcp: yes
  udp: yes
  sample-rate: 1                       # 1-in-N flow sampling
  max-flows: 100000
  max-packets-per-direction: 16        # caps SPLT length to ~32
  max-bytes-per-direction: 8192        # caps entropy histogram

  # Per-feature emit toggles. All default to yes when the plugin is enabled.
  emit:
    entropy: yes
    pcr: yes
    splt: yes
```

Any combination is valid (including `splt: no, entropy: no, pcr: yes`).
If all three are off the plugin refuses to register.

## Output format

```json
{
  "timestamp": "2026-04-29T01:14:22.018452Z",
  "flow_id": 17628341205823,
  "event_type": "payload_entropy",
  "src_ip": "10.1.2.45", "src_port": 49215,
  "dest_ip": "10.1.2.10", "dest_port": 443,
  "proto": "TCP",
  "payload_entropy": {
    "entropy_toserver": 7.94,
    "entropy_toclient": 7.91,
    "bytes_sampled_toserver": 8192,
    "bytes_sampled_toclient": 6234,

    "pcr": 0.568,

    "splt": "HhHhKHkkkk",
    "splt_lengths": [224, 198, 230, 211, 1340, 187, 1460, 1460, 1460, 870],
    "splt_iats_us": [0, 1842, 90, 12000, 250, 4500, 80, 80, 80, 90]
  }
}
```

Disabled signals are omitted entirely from the record (not emitted as
`null`). Enabled but no-data signals (e.g., entropy enabled but no packets
seen in one direction) drop only the affected fields.

## SPLT letter encoding

Each character in `splt` represents one observed packet, in arrival order
across both directions:

- **Case** — uppercase = client→server (toserver), lowercase = server→client.
- **Letter** — log2 size bucket of the packet's payload byte count:

| Letter | Size bucket |
|---|---|
| A / a | ≤ 2 |
| B / b | 3–4 |
| C / c | 5–8 |
| D / d | 9–16 |
| E / e | 17–32 |
| F / f | 33–64 |
| G / g | 65–128 |
| H / h | 129–256 |
| I / i | 257–512 |
| J / j | 513–1024 |
| K / k | 1025–2048+ |

`splt`, `splt_lengths`, and `splt_iats_us` are index-aligned: position `i`
in all three describes the same packet. `splt_iats_us[0]` is always 0
(no previous packet). Length is capped at 64 (default config: ≤32).

## Querying

```sql
-- Likely encrypted exfil
SELECT src_ip, dest_ip, dest_port, entropy_toserver, pcr,
       bytes_sampled_toserver, splt
FROM read_parquet('.../payload_entropy/...', union_by_name=true)
WHERE entropy_toserver >= 7.8
  AND pcr   >= 0.85
  AND bytes_sampled_toserver >= 1024
ORDER BY entropy_toserver DESC, pcr DESC;

-- Cluster by SPLT shape
SELECT splt, COUNT(*) AS flows
FROM read_parquet('.../payload_entropy/...', union_by_name=true)
WHERE splt IS NOT NULL
GROUP BY splt
ORDER BY flows DESC
LIMIT 50;

-- TLS-handshake-shaped flows: small Hello exchange + larger key/cert
SELECT src_ip, dest_ip, dest_port, splt, splt_lengths, splt_iats_us
FROM read_parquet('.../payload_entropy/...', union_by_name=true)
WHERE splt LIKE 'HhH%K%'
LIMIT 20;

-- Long inter-arrival times (possible C2 beaconing)
SELECT src_ip, dest_ip, dest_port,
       list_max(splt_iats_us) AS max_iat_us,
       splt
FROM read_parquet('.../payload_entropy/...', union_by_name=true)
WHERE list_max(splt_iats_us) > 10000000  -- > 10 seconds
ORDER BY max_iat_us DESC;
```

## Storage

| Field | EVE wire | Parquet (compressed) |
|---|---|---|
| Header (timestamp, flow_id, 5-tuple, proto) | ~200 B | ~30–50 B |
| Entropy + bytes_sampled + pcr | ~150 B | ~30 B |
| SPLT (≤32 packets default): `splt` + `splt_lengths` + `splt_iats_us` | ~250 B | ~50–100 B |
| **Total per record** | **~600 B** | **~120–180 B** |

At a million flows/day with all three signals on, that's ~600 MB EVE wire,
~150 MB on disk after compression. Disable any signal to cut that
proportionally.
