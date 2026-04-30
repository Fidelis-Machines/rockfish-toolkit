# Rockfish Suricata Transport Performance Plugin

Per-flow TCP and UDP performance metrics, emitted as `tcp_perf` and
`udp_perf` events through Suricata's normal eve-log pipeline. Whatever
`filetype:` your eve-log uses (regular file, unix_dgram, unix_stream,
syslog, redis) — these events go there too, mixed in with your existing
flow / dns / tls events.

| TCP signals          | UDP signals                          |
|----------------------|--------------------------------------|
| Three-way handshake RTT | Request/response RTT (paired)     |
| Retransmits per direction | Inter-arrival time (avg, stddev)|
| Out-of-order packets    | Per-direction byte/packet counts  |
| Zero-window events      |                                   |
| Window stats (min/avg/max) |                                |
| RST / FIN counts        |                                   |
| Termination reason (`fin` / `rst` / `timeout`) |        |

## Build

```sh
SURICATA_SRC=/path/to/configured/suricata-src make
# or, if libsuricata-config is on PATH:
make
```

The result is `rockfish-transport-perf.so`.

## Install

Copy the `.so` into Suricata's plugin directory and reference it from
`suricata.yaml`. Then enable `tcp_perf` and `udp_perf` under your existing
`eve-log.types:` list — that's it.

```yaml
plugins:
  - /usr/lib/suricata/plugins/rockfish-transport-perf.so

outputs:
  - eve-log:
      enabled: yes
      filetype: unix_stream     # or whatever you already use
      filename: /var/run/rockfish/rockfish.sock
      types:
        - alert
        - flow
        - dns
        - tls:
            extended: yes
        # ── Transport perf events ────────────────────────────────
        - tcp_perf
        - udp_perf

# Optional plugin tuning (all keys optional, defaults shown).
rockfish-transport-perf:
  enabled: yes
  tcp: yes
  udp: yes
  sample-rate: 1                     # 1-in-N flow sampling
  max-flows: 100000
  flow-idle-timeout: 60
  udp-rtt-pairing-window-ms: 2000
  emit:
    handshake-rtt: yes
    retransmits:   yes
    zero-window:   yes
    window-stats:  yes
    udp-rtt:       yes
    udp-jitter:    yes
```

No second socket. No second file. No `output-file` knob. The plugin
hands its events to Suricata's eve writer and Suricata routes them.

## Output format

Sample TCP record (lives in the same eve stream as flow/dns/tls):

```json
{
  "timestamp": "2026-04-28T17:32:11.018452Z",
  "flow_id": 17628341205823,
  "event_type": "tcp_perf",
  "src_ip": "10.1.2.45", "src_port": 49215,
  "dest_ip": "10.1.2.10", "dest_port": 443,
  "proto": "TCP",
  "tcp_perf": {
    "start_us": 1748365931018452,
    "end_us":   1748365941312009,
    "duration_us": 10293557,
    "handshake_rtt_us": 1842,
    "pkts_toserver": 84,  "pkts_toclient": 71,
    "bytes_toserver": 7224, "bytes_toclient": 11502,
    "retransmits_toserver": 1,
    "avg_window_toclient": 64240,
    "min_window_toclient": 60128,
    "max_window_toclient": 65535,
    "fin_count": 2,
    "close_reason": "fin"
  }
}
```

Sample UDP record:

```json
{
  "timestamp": "2026-04-28T17:32:11.118452Z",
  "flow_id": 17628341219991,
  "event_type": "udp_perf",
  "src_ip": "10.1.2.45", "src_port": 53412,
  "dest_ip": "10.1.2.1", "dest_port": 53,
  "proto": "UDP",
  "udp_perf": {
    "start_us": 1748365931118452,
    "end_us":   1748365931145812,
    "duration_us": 27360,
    "pkts_toserver": 1, "pkts_toclient": 1,
    "bytes_toserver": 64, "bytes_toclient": 188,
    "rtt_count": 1,
    "rtt_min_us": 27188, "rtt_max_us": 27188,
    "rtt_avg_us": 27188.0
  }
}
```

## How rockfish-perf consumes this

`rockfish-perf` reads the Suricata eve socket and now sees `tcp_perf` /
`udp_perf` mixed in with `flow` / `dns`. The fields surface in the
per-asset feature vector as:

| Feature                    | Source                             |
|----------------------------|-----------------------------------|
| `tcp_handshake_rtt_ms_avg` | `tcp_perf.handshake_rtt_us`       |
| `tcp_retransmit_ratio`     | retransmits / packets             |
| `tcp_zero_window_ratio`    | zero_window / packets             |
| `tcp_out_of_order_ratio`   | out_of_order / packets            |
| `udp_rtt_avg_ms`           | `udp_perf.rtt_avg_us`             |
| `udp_jitter_avg_ms`        | mean of per-direction `iat_stddev_us` |

These dimensions are added to the HBOS drift baseline automatically.
