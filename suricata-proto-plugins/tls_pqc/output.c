/* Rockfish Suricata TLS PQC Plugin - Output
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Per-flow PQC verdict emitted as a `pqc` eve event:
 *
 *   {
 *     "event_type": "pqc",
 *     "src_ip": "10.1.4.20", "src_port": 51234,
 *     "dest_ip": "1.2.3.4",  "dest_port": 443,
 *     "proto": "TCP", "flow_id": 0x...,
 *     "pqc": {
 *       "tls_version":            "TLS 1.3",
 *       "client_offered_pqc":     true,
 *       "client_supported_groups": [4588, 29, 23, 24],
 *       "server_chosen_group":    29,
 *       "server_chosen_group_name": "X25519",
 *       "server_chosen_pqc":      false,
 *       "nist_compliant":         false,
 *       "exposure_class":         "server_lagging"
 *     }
 *   }
 *
 * Hooks:
 *   - Packet logger (TCP, first N pkts/dir): hands payload bytes to the
 *     Rust handshake parser via rs_pqc_observe.
 *   - Flow-end logger: reads the accumulated verdict via rs_pqc_take_stats
 *     and emits the eve event.
 *
 * Mirrors the C+Rust split established by payload_entropy and
 * transport_signals — Suricata macro / struct access stays in C; all
 * substantive logic (TLS parsing, PQC classification, per-flow state) is
 * in the Rust staticlib.
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

#include "tls-pqc.h"

#define PQC_MAX_GROUPS 32   /* must match PQC_MAX_GROUPS in lib.rs */

/* ============================================================================
 * Rust FFI
 * ========================================================================= */

extern int  rs_pqc_init(const char *config_json);
extern void rs_pqc_deinit(void);
extern int  rs_pqc_observe(uint64_t flow_hash, uint8_t direction,
                           const uint8_t *payload, uint32_t payload_len);

typedef struct PqcStats_ {
    uint8_t  valid;

    uint8_t  client_offered_pqc;
    uint8_t  server_chosen_pqc;
    uint8_t  nist_compliant;

    uint8_t  has_client_groups;
    uint8_t  has_server_chosen;
    uint8_t  has_tls_version;

    uint16_t server_chosen_group;
    uint16_t tls_version_be;

    uint8_t  exposure_class[16];
    uint8_t  server_chosen_group_name[32];

    uint16_t client_groups_len;
    uint16_t client_supported_groups[PQC_MAX_GROUPS];
} PqcStats;

extern uint8_t rs_pqc_take_stats(uint64_t flow_hash, PqcStats *out);

void pqc_log_notice(const char *m) { SCLogNotice("tls-pqc: %s", m); }
void pqc_log_error(const char *m)  { SCLogError("tls-pqc: %s", m); }

/* ============================================================================
 * Plugin state
 * ========================================================================= */

static bool     g_pqc_initialized = false;
static uint32_t g_pqc_sample_n    = 1;

/* ============================================================================
 * Helpers
 * ========================================================================= */

static inline uint8_t pkt_direction(const Packet *p)
{
    if (p->flow == NULL) return 1;
    return PKT_IS_TOSERVER(p) ? 0 : 1;
}

static const char *tls_version_label(uint16_t ver_be)
{
    switch (ver_be) {
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default:     return NULL;
    }
}

/* ============================================================================
 * Packet logger
 * ========================================================================= */

static bool PqcPacketCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    (void)tv; (void)thread_data;
    if (!g_pqc_initialized || p == NULL || p->flow == NULL) return false;
    if (p->payload_len == 0) return false;
    return PacketIsTCP(p);
}

static int PqcPacketLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    (void)tv; (void)thread_data;
    if (!g_pqc_initialized || p == NULL || p->flow == NULL) return 0;
    if (p->payload_len == 0) return 0;

    if (g_pqc_sample_n > 1) {
        if ((p->flow->flow_hash % g_pqc_sample_n) != 0) return 0;
    }

    rs_pqc_observe(p->flow->flow_hash, pkt_direction(p),
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
    SCJbSetString(jb, "event_type", "pqc");
    SCJbSetString(jb, "src_ip",     srcip);
    SCJbSetUint  (jb, "src_port",   f->sp);
    SCJbSetString(jb, "dest_ip",    dstip);
    SCJbSetUint  (jb, "dest_port",  f->dp);
    SCJbSetString(jb, "proto",      "TCP");
    return jb;
}

static int PqcFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    if (!g_pqc_initialized || f == NULL) return 0;
    if (f->proto != IPPROTO_TCP) return 0;

    PqcStats s;
    memset(&s, 0, sizeof(s));
    if (!rs_pqc_take_stats(f->flow_hash, &s) || !s.valid) return 0;

    OutputJsonThreadCtx *thread = thread_data;
    SCJsonBuilder *jb = build_eve_header_for_flow(f);
    if (jb == NULL) return 0;

    SCJbOpenObject(jb, "pqc");

    /* TLS version label (only when we extracted one). */
    if (s.has_tls_version) {
        const char *lbl = tls_version_label(s.tls_version_be);
        if (lbl != NULL) {
            SCJbSetString(jb, "tls_version", lbl);
        } else {
            SCJbSetUint(jb, "tls_version_raw", s.tls_version_be);
        }
    }

    SCJbSetBool(jb, "client_offered_pqc", s.client_offered_pqc ? true : false);

    /* Client offered list — emit as a JSON array of integer codepoints so
     * downstream (rockfish-report) can map them to names with the same
     * table the plugin uses (kept in sync via groups.rs / lib.rs). */
    if (s.has_client_groups) {
        SCJbOpenArray(jb, "client_supported_groups");
        for (uint16_t i = 0; i < s.client_groups_len; i++) {
            SCJbAppendUint(jb, s.client_supported_groups[i]);
        }
        SCJbClose(jb);
    }

    if (s.has_server_chosen) {
        SCJbSetUint(jb, "server_chosen_group", s.server_chosen_group);
        if (s.server_chosen_group_name[0] != 0) {
            SCJbSetString(jb, "server_chosen_group_name",
                          (const char *)s.server_chosen_group_name);
        }
        SCJbSetBool(jb, "server_chosen_pqc", s.server_chosen_pqc ? true : false);
    }

    SCJbSetBool(jb, "nist_compliant", s.nist_compliant ? true : false);
    SCJbSetString(jb, "exposure_class", (const char *)s.exposure_class);

    SCJbClose(jb);

    OutputJsonBuilderBuffer(tv, NULL, f, jb, thread);
    SCJbFree(jb);
    return 0;
}

/* ============================================================================
 * Thread init/deinit
 * ========================================================================= */

static TmEcode PqcPacketThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    (void)tv; (void)initdata;
    *data = NULL;
    return TM_ECODE_OK;
}

static TmEcode PqcPacketThreadDeinit(ThreadVars *tv, void *data)
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

void RockfishTlsPqcRegister(void)
{
    int  enabled                = 1;
    int  tcp_enabled            = 1;
    intmax_t sample_n           = 1;
    intmax_t max_flows          = 100000;
    intmax_t max_packets_per_dir = 8;

    SCConfNode *conf = SCConfGetNode("rockfish-tls-pqc");
    if (conf != NULL) {
        intmax_t ival;
        int bval;
        if (SCConfGetChildValueBool(conf, "enabled", &bval) == 1) enabled = bval;
        if (SCConfGetChildValueBool(conf, "tcp", &bval) == 1) tcp_enabled = bval;
        if (SCConfGetChildValueInt(conf, "sample-rate", &ival) == 1 && ival > 0) sample_n = ival;
        if (SCConfGetChildValueInt(conf, "max-flows", &ival) == 1 && ival > 0) max_flows = ival;
        if (SCConfGetChildValueInt(conf, "max-packets-per-direction", &ival) == 1 && ival > 0)
            max_packets_per_dir = ival;
    }

    if (!enabled) {
        SCLogNotice("Rockfish TLS PQC disabled by configuration");
        return;
    }
    if (!tcp_enabled) {
        SCLogNotice("Rockfish TLS PQC: tcp disabled — not registering");
        return;
    }

    g_pqc_sample_n = (uint32_t)sample_n;

    char cfg[512];
    int  off = 0, first = 1;
    cfg[off++] = '{';
    off = json_bool(cfg, off, sizeof(cfg), &first, "tcp_enabled", tcp_enabled);
    off = json_int (cfg, off, sizeof(cfg), &first, "sample_rate", sample_n);
    off = json_int (cfg, off, sizeof(cfg), &first, "max_flows", max_flows);
    off = json_int (cfg, off, sizeof(cfg), &first, "max_packets_per_dir", max_packets_per_dir);
    if (off < (int)sizeof(cfg) - 2) {
        cfg[off++] = '}';
        cfg[off]   = '\0';
    } else {
        cfg[sizeof(cfg) - 1] = '\0';
    }

    if (rs_pqc_init(cfg) != 0) {
        SCLogError("Failed to initialize tls-pqc state");
        return;
    }
    g_pqc_initialized = true;

    if (SCOutputRegisterPacketLogger(LOGGER_USER, "RockfishTlsPqcPkt",
                                      PqcPacketLogger, PqcPacketCondition,
                                      NULL, PqcPacketThreadInit, PqcPacketThreadDeinit) != 0) {
        SCLogError("Failed to register tls-pqc packet logger");
        rs_pqc_deinit();
        g_pqc_initialized = false;
        return;
    }

    OutputRegisterFlowSubModule(LOGGER_USER, "eve-log",
        "RockfishTlsPqcLog", "eve-log.pqc",
        OutputJsonLogInitSub, PqcFlowLogger,
        JsonLogThreadInit, JsonLogThreadDeinit);

    /* ── Startup banner ────────────────────────────────────────────── */
    SCLogNotice("════════════════════════════════════════════════════════════");
    SCLogNotice("  Rockfish TLS PQC v%s — LOADED",
                ROCKFISH_TLS_PQC_VERSION);
    SCLogNotice("    TCP:                       %s", tcp_enabled ? "enabled" : "disabled");
    SCLogNotice("    Sample rate:               1/%u", (unsigned)sample_n);
    SCLogNotice("    Max flows:                 %jd", max_flows);
    SCLogNotice("    Max packets per direction: %jd", max_packets_per_dir);
    SCLogNotice("    NIST IR 8547 PQC compliance verdict:");
    SCLogNotice("      X25519MLKEM768 (4588), ML-KEM-512/1024 (4587/4589),");
    SCLogNotice("      X25519Kyber768Draft00 (25497) — flagged PQ-safe");
    SCLogNotice("    Output: eve-log (add 'pqc' to eve-log.types)");
    SCLogNotice("════════════════════════════════════════════════════════════");
}
