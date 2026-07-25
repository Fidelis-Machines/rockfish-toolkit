# Rockfish Suricata TLS PQC Plugin

Per-handshake post-quantum key-exchange classification, per [NIST IR 8547]
transition guidance.

For every TLS-bearing flow Suricata sees, the plugin extracts two facts the
stock TLS event log doesn't expose:

| Field | Where it comes from | Why stock Suricata doesn't emit it |
|---|---|---|
| `client_supported_groups` | ClientHello extension type 10 | Suricata parses this list only to feed into the JA3 fingerprint, then frees it. The raw codepoints never reach the eve log. |
| `server_chosen_group` | TLS 1.3 ServerHello key_share (extension type 51) | Suricata's TLS parser doesn't read this extension at all (verified against `app-layer-ssl.c` in Suricata 7.0). |

It then composes a NIST IR 8547 compliance verdict and emits one `pqc`
eve event per flow.

[NIST IR 8547]: https://csrc.nist.gov/pubs/ir/8547/final

## Eve event shape

```json
{
  "event_type": "pqc",
  "src_ip": "10.1.4.20",   "src_port": 51234,
  "dest_ip": "203.0.113.4", "dest_port": 443,
  "proto": "TCP",
  "flow_id": 12345678901234,
  "pqc": {
    "tls_version":              "TLS 1.3",
    "client_offered_pqc":       true,
    "client_supported_groups":  [4588, 29, 23, 24],
    "server_chosen_group":      29,
    "server_chosen_group_name": "X25519",
    "server_chosen_pqc":        false,
    "nist_compliant":           false,
    "exposure_class":           "server_lagging"
  }
}
```

`exposure_class` is one of:

| Value | Meaning |
|---|---|
| `"compliant"`     | Server actually negotiated a PQ KEM. NIST-safe per IR 8547. |
| `"server_lagging"` | Client offered PQ, server chose classical. Silent exposure. |
| `"client_lagging"` | Client never offered PQ. Definitely exposed. |
| `"partial"`        | One half of the handshake observed (typical for TLS 1.2). |
| `"unknown"`        | Couldn't classify (no recognized groups). |

## Supported post-quantum codepoints

Recognised as PQ (`server_chosen_pqc: true`, `nist_compliant: true` when the server picks one):

| Codepoint | Name | Status |
|---|---|---|
| 4587 | ML-KEM-512 | NIST FIPS 203 |
| **4588** | **X25519MLKEM768** | NIST FIPS 203 hybrid — what Chrome / Cloudflare ship |
| 4589 | ML-KEM-1024 | NIST FIPS 203 |
| 25497 | X25519Kyber768Draft00 | Pre-standardisation Kyber hybrid (Chrome 116-124) |
| 25498 | SecP256r1Kyber768Draft00 | Pre-standardisation Kyber hybrid |

The full classification table — including classical ECDHE (X25519, secp256r1,
secp384r1, …) and FFDHE — is in [`src/groups.rs`](src/groups.rs).

## TLS version coverage

| Version | Detection |
|---|---|
| **TLS 1.3** | Full — ClientHello supported_groups + ServerHello key_share. `nist_compliant` is meaningful. |
| TLS 1.2     | Partial — ClientHello supported_groups only. ServerHello has no key_share extension; the chosen ECDHE curve is in ServerKeyExchange (a later record, often spanning multiple TCP segments). The verdict is `"partial"` for these flows. |
| TLS 1.0/1.1 | No PQ key exchange exists in these versions; the verdict is `"client_lagging"`. |

For NIST IR 8547 purposes, TLS 1.2 is classically vulnerable regardless of
the chosen ECDHE curve — the absence of a PQ KEM means it can't be
PQ-safe. So `"partial"` on TLS 1.2 is equivalent to non-compliant; we
emit the lower-confidence label so downstream reports can rank these
below confirmed `"server_lagging"` cases.

## Build

Mirrors the C+Rust split used by `payload_entropy` and `transport_signals`
in this toolkit. The C side handles Suricata's plugin API (macros + struct
field access via the Suricata headers); the Rust side handles all the
parsing and classification logic.

```sh
make                     # builds rockfish-tls-pqc.so
make test                # cargo test (14 tests, no Suricata runtime needed)
make install             # → /usr/lib/suricata/plugins/
```

Build requirements:

- Either `libsuricata-config` on `$PATH`, **or** Suricata source tree at
  `/development/suricata` (override with `SURICATA_SRC=/path`).
- Rust toolchain ≥ 1.75 (any recent stable).

## Configuration (`suricata.yaml`)

```yaml
plugins:
  - /usr/lib/suricata/plugins/rockfish-tls-pqc.so

outputs:
  - eve-log:
      filetype: unix_stream
      filename: /var/run/rockfish/rockfish.sock
      types:
        - alert
        - flow
        - tls
        - pqc           # ← enable this plugin's output

rockfish-tls-pqc:
  enabled: yes
  tcp: yes                              # required; QUIC is out of scope for v1
  sample-rate: 1                        # 1-in-N flow sampling
  max-flows: 100000                     # per-flow state cap
  max-packets-per-direction: 8          # ClientHello + ServerHello fit in 1-2
```

## How it works

1. **Packet logger** (TCP only, payload-bearing, capped per direction):
   each packet's payload bytes are handed to the Rust parser via
   `rs_pqc_observe`.

2. **Parser** ([`src/parser.rs`](src/parser.rs)) walks the TLS record
   layer, locates ClientHello / ServerHello handshake messages, and reads
   the relevant extensions:

   - From the ClientHello: extension type 10 (supported_groups) →
     full codepoint list.
   - From the ServerHello: extension type 51 (key_share, TLS 1.3 only)
     → the server's chosen NamedGroup.
   - From the ServerHello: extension type 43 (supported_versions) →
     the actual negotiated TLS version (since legacy_version is locked
     at 0x0303 in TLS 1.3).

   Every length read is bounds-checked; malformed inputs degrade to
   `None` rather than panicking. The truncation fuzz check in the unit
   tests exercises every prefix of a known-good handshake.

3. **State** ([`src/state.rs`](src/state.rs)) tracks one entry per flow,
   capped by `max-flows` (10× the default Suricata flow table for safety).
   Once both halves are observed, no further packets on that flow are
   inspected.

4. **Verdict** is computed at flow end:

   ```text
   client_offered_pqc  = any(client_supported_groups, is_pq)
   server_chosen_pqc   = classify(server_chosen_group).is_pq()
   nist_compliant      = server_chosen_pqc
   exposure_class      = ...
   ```

5. **Flow logger** emits the `pqc` event via Suricata's eve-log subsystem
   (`OutputRegisterFlowSubModule` with key `eve-log.pqc`).

## Downstream consumption

In the `rockfish-report` pipeline, `pqc` events flow into the same
Hive-partitioned Parquet writer as `tls`, `tcp_perf`, `udp_perf`, and
`payload_entropy`. A new query reads `pqc.parquet` and surfaces
non-compliant handshakes on the TLS page under "NIST PQC Compliance".

## Out of scope for v1

- **QUIC (TLS over UDP)** — handshake byte format is the same but framed
  differently. Future work.
- **TLS 1.2 ServerKeyExchange parsing** — the chosen ECDHE curve lives
  in a later record that often spans TCP segments. For NIST compliance
  the answer is "non-compliant" regardless, so the cost-benefit isn't
  there.
- **Encrypted ClientHello (ECH)** — when the inner ClientHello is
  encrypted we can only see the outer one. ECH adoption is still low;
  we'll add ECH-aware handling once it's common.

## License

GPL-2.0-only — same as Suricata.
