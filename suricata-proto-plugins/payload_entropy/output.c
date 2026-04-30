/* Rockfish Suricata Payload Entropy Plugin - Output
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Three configurable signals per flow, all over the same sampled packet
 * window (capped by max-packets-per-direction):
 *   - Shannon byte entropy (bits/byte) per direction
 *   - PCR (producer/consumer ratio) over sampled bytes
 *   - SPLT — `splt_lengths` (u16), `splt_iats_us` (u32), `splt` (letter
 *     sequence with case = direction)
 *
 * Each signal is independently enable/disable-able under the plugin's
 * `emit:` block in suricata.yaml.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "threadvars.h"
#include "output.h"
#include "output-json.h"
#include "output-packet.h"
#include "output-flow.h"
#include "util-debug.h"
#include "util-print.h"
#include "conf.h"
#include "flow.h"
#include "decode.h"
#include "rust.h"

#include "payload-entropy.h"

#define PE_SPLT_MAX 64    /* must match SPLT_MAX_LEN in state.rs */

/* ============================================================================
 * Rust FFI
 * ========================================================================= */

extern int  rs_pe_init(const char *config_json);
extern void rs_pe_deinit(void);
extern int  rs_pe_observe(uint64_t flow_hash, int64_t ts_us, uint8_t direction,
                          const uint8_t *payload, uint32_t payload_len);

typedef struct PeStats_ {
    uint8_t  valid;

    uint8_t  emit_entropy;
    uint8_t  emit_pcr;
    uint8_t  emit_splt;

    uint8_t  has_entropy_to_server;
    uint8_t  has_entropy_to_client;
    double   entropy_to_server;
    double   entropy_to_client;
    uint32_t bytes_sampled_to_server;
    uint32_t bytes_sampled_to_client;

    uint8_t  has_pcr;
    double   pcr;

    uint8_t  splt_len;
    uint8_t  splt_letters[PE_SPLT_MAX];
    uint16_t splt_lengths[PE_SPLT_MAX];
    uint32_t splt_iats_us[PE_SPLT_MAX];
} PeStats;

extern uint8_t rs_pe_take_stats(uint64_t flow_hash, PeStats *out);

void pe_log_notice(const char *m) { SCLogNotice("payload-entropy: %s", m); }
void pe_log_error(const char *m)  { SCLogError("payload-entropy: %s", m); }

/* ============================================================================
 * Plugin state
 * ========================================================================= */

static bool     g_pe_initialized = false;
static bool     g_pe_tcp_enabled = true;
static bool     g_pe_udp_enabled = true;
static uint32_t g_pe_sample_n    = 1;

/* ============================================================================
 * Helpers
 * ========================================================================= */

static inline int64_t pkt_ts_us(const Packet *p)
{
    return (int64_t)SCTIME_SECS(p->ts) * 1000000 + (int64_t)SCTIME_USECS(p->ts);
}

static inline uint8_t pkt_direction(const Packet *p)
{
    if (p->flow == NULL) return 1;
    return PKT_IS_TOSERVER(p) ? 0 : 1;
}

/* ============================================================================
 * Packet logger
 * ========================================================================= */

static bool PePacketCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    (void)tv; (void)thread_data;
    if (!g_pe_initialized || p == NULL || p->flow == NULL) return false;
    if (p->payload_len == 0) return false;
    if (PacketIsTCP(p)) return g_pe_tcp_enabled;
    if (PacketIsUDP(p)) return g_pe_udp_enabled;
    return false;
}

static int PePacketLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    (void)tv; (void)thread_data;
    if (!g_pe_initialized || p == NULL || p->flow == NULL) return 0;
    if (p->payload_len == 0) return 0;

    if (g_pe_sample_n > 1) {
        if ((p->flow->flow_hash % g_pe_sample_n) != 0) return 0;
    }

    rs_pe_observe(p->flow->flow_hash, pkt_ts_us(p), pkt_direction(p),
                  p->payload, p->payload_len);
    return 0;
}

/* ============================================================================
 * Flow-end eve sub-module
 * ========================================================================= */

static SCJsonBuilder *build_eve_header_for_flow(const Flow *f)
{
    char srcip[46] = {0}, dstip[46] = {0};
    char timebuf[64];

    SCTime_t ts = TimeGet();
    CreateIsoTimeString(ts, timebuf, sizeof(timebuf));

    if (FLOW_IS_IPV4(f)) {
        PrintInet(AF_INET, (const void *)&f->src.addr_data32[0], srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)&f->dst.addr_data32[0], dstip, sizeof(dstip));
    } else if (FLOW_IS_IPV6(f)) {
        PrintInet(AF_INET6, (const void *)&f->src.address, srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)&f->dst.address, dstip, sizeof(dstip));
    }

    SCJsonBuilder *jb = SCJbNewObject();
    if (jb == NULL) return NULL;
    SCJbSetString(jb, "timestamp",  timebuf);
    SCJbSetUint  (jb, "flow_id",    f->flow_hash);
    SCJbSetString(jb, "event_type", "payload_entropy");
    SCJbSetString(jb, "src_ip",     srcip);
    SCJbSetUint  (jb, "src_port",   f->sp);
    SCJbSetString(jb, "dest_ip",    dstip);
    SCJbSetUint  (jb, "dest_port",  f->dp);
    SCJbSetString(jb, "proto",      f->proto == IPPROTO_TCP ? "TCP" : "UDP");
    return jb;
}

static int PeFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    if (!g_pe_initialized || f == NULL) return 0;
    if (f->proto != IPPROTO_TCP && f->proto != IPPROTO_UDP) return 0;

    PeStats s;
    memset(&s, 0, sizeof(s));
    if (!rs_pe_take_stats(f->flow_hash, &s) || !s.valid) return 0;

    OutputJsonThreadCtx *thread = thread_data;
    SCJsonBuilder *jb = build_eve_header_for_flow(f);
    if (jb == NULL) return 0;

    SCJbOpenObject(jb, "payload_entropy");

    /* ── Shannon entropy + bytes_sampled ────────────────────────────── */
    if (s.emit_entropy) {
        if (s.has_entropy_to_server) {
            SCJbSetFloat(jb, "entropy_toserver", s.entropy_to_server);
        }
        if (s.has_entropy_to_client) {
            SCJbSetFloat(jb, "entropy_toclient", s.entropy_to_client);
        }
        SCJbSetUint(jb, "bytes_sampled_toserver", s.bytes_sampled_to_server);
        SCJbSetUint(jb, "bytes_sampled_toclient", s.bytes_sampled_to_client);
    }

    /* ── PCR (producer/consumer ratio) ─────────────────────────────── */
    if (s.emit_pcr && s.has_pcr) {
        SCJbSetFloat(jb, "pcr", s.pcr);
    }

    /* ── SPLT (length + IAT arrays + letter string) ────────────────── */
    if (s.emit_splt && s.splt_len > 0) {
        SCJbSetStringFromBytes(jb, "splt", s.splt_letters, (uint32_t)s.splt_len);

        SCJbOpenArray(jb, "splt_lengths");
        for (uint8_t i = 0; i < s.splt_len; i++) {
            SCJbAppendUint(jb, s.splt_lengths[i]);
        }
        SCJbClose(jb);

        SCJbOpenArray(jb, "splt_iats_us");
        for (uint8_t i = 0; i < s.splt_len; i++) {
            SCJbAppendUint(jb, s.splt_iats_us[i]);
        }
        SCJbClose(jb);
    }

    SCJbClose(jb);

    OutputJsonBuilderBuffer(tv, NULL, f, jb, thread);
    SCJbFree(jb);
    return 0;
}

/* ============================================================================
 * Thread init/deinit
 * ========================================================================= */

static TmEcode PePacketThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    (void)tv; (void)initdata;
    *data = NULL;
    return TM_ECODE_OK;
}

static TmEcode PePacketThreadDeinit(ThreadVars *tv, void *data)
{
    (void)tv; (void)data;
    return TM_ECODE_OK;
}

/* ============================================================================
 * Config bridging
 * ========================================================================= */

static int json_bool(char *buf, int off, int cap, int *first,
                     const char *key, int val)
{
    int n = snprintf(buf + off, cap - off, "%s\"%s\":%s",
                     *first ? "" : ",", key, val ? "true" : "false");
    if (n < 0 || n >= cap - off) return off;
    *first = 0;
    return off + n;
}

static int json_int(char *buf, int off, int cap, int *first,
                    const char *key, intmax_t val)
{
    int n = snprintf(buf + off, cap - off, "%s\"%s\":%jd",
                     *first ? "" : ",", key, val);
    if (n < 0 || n >= cap - off) return off;
    *first = 0;
    return off + n;
}

void RockfishPayloadEntropyRegister(void)
{
    int  enabled               = 1;
    int  tcp_enabled           = 1;
    int  udp_enabled           = 1;
    intmax_t sample_n          = 1;
    intmax_t max_flows         = 100000;
    intmax_t max_packets_per_dir = 16;
    intmax_t max_bytes_per_dir = 8192;
    int  emit_entropy          = 1;
    int  emit_pcr              = 1;
    int  emit_splt             = 1;

    SCConfNode *conf = SCConfGetNode("rockfish-payload-entropy");
    if (conf != NULL) {
        intmax_t ival;
        int bval;
        if (SCConfGetChildValueBool(conf, "enabled", &bval) == 1) enabled = bval;
        if (SCConfGetChildValueBool(conf, "tcp", &bval) == 1) tcp_enabled = bval;
        if (SCConfGetChildValueBool(conf, "udp", &bval) == 1) udp_enabled = bval;
        if (SCConfGetChildValueInt(conf, "sample-rate", &ival) == 1 && ival > 0) sample_n = ival;
        if (SCConfGetChildValueInt(conf, "max-flows", &ival) == 1 && ival > 0) max_flows = ival;
        if (SCConfGetChildValueInt(conf, "max-packets-per-direction", &ival) == 1 && ival > 0)
            max_packets_per_dir = ival;
        if (SCConfGetChildValueInt(conf, "max-bytes-per-direction", &ival) == 1 && ival > 0)
            max_bytes_per_dir = ival;

        SCConfNode *emit = SCConfNodeLookupChild(conf, "emit");
        if (emit != NULL) {
            if (SCConfGetChildValueBool(emit, "entropy", &bval) == 1) emit_entropy = bval;
            if (SCConfGetChildValueBool(emit, "pcr", &bval) == 1) emit_pcr = bval;
            if (SCConfGetChildValueBool(emit, "splt", &bval) == 1) emit_splt = bval;
        }
    }

    if (!enabled) {
        SCLogNotice("Rockfish Payload Entropy disabled by configuration");
        return;
    }
    if (!tcp_enabled && !udp_enabled) {
        SCLogNotice("Rockfish Payload Entropy: tcp and udp both disabled — not registering");
        return;
    }
    if (!emit_entropy && !emit_pcr && !emit_splt) {
        SCLogNotice("Rockfish Payload Entropy: all emit toggles off — not registering");
        return;
    }

    g_pe_tcp_enabled = (tcp_enabled != 0);
    g_pe_udp_enabled = (udp_enabled != 0);
    g_pe_sample_n    = (uint32_t)sample_n;

    char cfg[1024];
    int  off = 0, first = 1;
    cfg[off++] = '{';
    off = json_bool(cfg, off, sizeof(cfg), &first, "tcp_enabled", tcp_enabled);
    off = json_bool(cfg, off, sizeof(cfg), &first, "udp_enabled", udp_enabled);
    off = json_int (cfg, off, sizeof(cfg), &first, "sample_rate", sample_n);
    off = json_int (cfg, off, sizeof(cfg), &first, "max_flows", max_flows);
    off = json_int (cfg, off, sizeof(cfg), &first, "max_packets_per_dir", max_packets_per_dir);
    off = json_int (cfg, off, sizeof(cfg), &first, "max_bytes_per_dir", max_bytes_per_dir);
    /* Nested emit object so it deserialises into EmitConfig. */
    {
        int n = snprintf(cfg + off, sizeof(cfg) - off,
                         "%s\"emit\":{\"entropy\":%s,\"pcr\":%s,\"splt\":%s}",
                         first ? "" : ",",
                         emit_entropy ? "true" : "false",
                         emit_pcr     ? "true" : "false",
                         emit_splt    ? "true" : "false");
        if (n > 0 && n < (int)(sizeof(cfg) - off)) {
            off += n;
            first = 0;
        }
    }
    if (off < (int)sizeof(cfg) - 2) {
        cfg[off++] = '}';
        cfg[off]   = '\0';
    } else {
        cfg[sizeof(cfg) - 1] = '\0';
    }

    if (rs_pe_init(cfg) != 0) {
        SCLogError("Failed to initialize payload-entropy state");
        return;
    }
    g_pe_initialized = true;

    if (SCOutputRegisterPacketLogger(LOGGER_USER, "RockfishPayloadEntropyPkt",
                                      PePacketLogger, PePacketCondition,
                                      NULL, PePacketThreadInit, PePacketThreadDeinit) != 0) {
        SCLogError("Failed to register payload-entropy packet logger");
        rs_pe_deinit();
        g_pe_initialized = false;
        return;
    }

    OutputRegisterFlowSubModule(LOGGER_USER, "eve-log",
        "RockfishPayloadEntropyLog", "eve-log.payload_entropy",
        OutputJsonLogInitSub, PeFlowLogger,
        JsonLogThreadInit, JsonLogThreadDeinit);

    /* ── Startup banner ────────────────────────────────────────────── */
    SCLogNotice("════════════════════════════════════════════════════════════");
    SCLogNotice("  Rockfish Payload Entropy v%s — LOADED",
                ROCKFISH_PAYLOAD_ENTROPY_VERSION);
    SCLogNotice("    TCP:                       %s", tcp_enabled ? "enabled" : "disabled");
    SCLogNotice("    UDP:                       %s", udp_enabled ? "enabled" : "disabled");
    SCLogNotice("    Sample rate:               1/%u", (unsigned)sample_n);
    SCLogNotice("    Max flows:                 %jd", max_flows);
    SCLogNotice("    Max packets per direction: %jd", max_packets_per_dir);
    SCLogNotice("    Max bytes per direction:   %jd", max_bytes_per_dir);
    SCLogNotice("    Emit:                      entropy=%s pcr=%s splt=%s",
                emit_entropy ? "yes" : "no",
                emit_pcr     ? "yes" : "no",
                emit_splt    ? "yes" : "no");
    SCLogNotice("    Output:                    via eve-log (add 'payload_entropy' to eve-log.types)");
    SCLogNotice("════════════════════════════════════════════════════════════");
}
