/* Rockfish Suricata Transport Signals Plugin - Output
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Emits tcp_signal and udp_signal events through Suricata's own eve-log
 * subsystem. The plugin does NOT manage its own output destination —
 * users enable it under `eve-log.types: [tcp_signal, udp_signal]` and
 * the events flow to whatever filetype eve-log is configured for (regular
 * file, unix_dgram, unix_stream, redis, syslog).
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

#include "transport-signals.h"

/* ============================================================================
 * Rust FFI — state management
 * ========================================================================= */

extern int  rs_tp_init(const char *config_json);
extern void rs_tp_deinit(void);

extern int  rs_tp_observe_tcp(
    uint64_t flow_hash, int64_t ts_us,
    const uint8_t *src_ip, uint32_t src_ip_len,
    const uint8_t *dst_ip, uint32_t dst_ip_len,
    uint16_t src_port, uint16_t dst_port,
    uint8_t  direction, uint8_t  tcp_flags,
    uint32_t seq, uint32_t ack,
    uint16_t window, uint8_t  wscale,
    uint32_t payload_len);

extern int  rs_tp_observe_udp(
    uint64_t flow_hash, int64_t ts_us,
    const uint8_t *src_ip, uint32_t src_ip_len,
    const uint8_t *dst_ip, uint32_t dst_ip_len,
    uint16_t src_port, uint16_t dst_port,
    uint8_t  direction, uint32_t payload_len);

/* ── Stats export structs (mirror lib.rs definitions exactly) ───────── */

typedef struct TpTcpStats_ {
    uint8_t  valid;
    int64_t  start_us;
    int64_t  end_us;
    int64_t  duration_us;
    uint8_t  has_handshake_rtt;
    int64_t  handshake_rtt_us;
    uint8_t  has_first_byte_ts;
    uint8_t  has_first_byte_tc;
    int64_t  first_byte_toserver_us;
    int64_t  first_byte_toclient_us;
    uint64_t retransmits_toserver, retransmits_toclient;
    uint64_t out_of_order_toserver, out_of_order_toclient;
    uint64_t zero_window_toserver, zero_window_toclient;
    uint64_t rst_count, fin_count;
    uint8_t  has_window_stats_ts;
    uint8_t  has_window_stats_tc;
    uint32_t avg_window_toserver;
    uint32_t min_window_toserver;
    uint32_t max_window_toserver;
    uint32_t avg_window_toclient;
    uint32_t min_window_toclient;
    uint32_t max_window_toclient;
    uint8_t  close_reason[16];
    uint8_t  emit_handshake_rtt;
    uint8_t  emit_retransmits;
    uint8_t  emit_zero_window;
    uint8_t  emit_window_stats;
} TpTcpStats;

typedef struct TpUdpStats_ {
    uint8_t  valid;
    int64_t  start_us;
    int64_t  end_us;
    int64_t  duration_us;
    uint8_t  has_first_byte_ts;
    uint8_t  has_first_byte_tc;
    int64_t  first_byte_toserver_us;
    int64_t  first_byte_toclient_us;
    uint8_t  has_rtt;
    uint64_t rtt_count;
    int64_t  rtt_min_us, rtt_max_us;
    double   rtt_avg_us;
    uint8_t  has_rtt_stddev;
    double   rtt_stddev_us;
    uint8_t  has_iat_ts;
    double   iat_avg_toserver_us;
    uint8_t  has_iat_tc;
    double   iat_avg_toclient_us;
    uint8_t  has_iat_stddev_ts;
    double   iat_stddev_toserver_us;
    uint8_t  has_iat_stddev_tc;
    double   iat_stddev_toclient_us;
    uint8_t  emit_udp_rtt;
    uint8_t  emit_udp_jitter;
} TpUdpStats;

extern uint8_t rs_tp_take_tcp_stats(uint64_t flow_hash, TpTcpStats *out);
extern uint8_t rs_tp_take_udp_stats(uint64_t flow_hash, TpUdpStats *out);

/* ============================================================================
 * Logging shims (used by Rust FFI)
 * ========================================================================= */

void tp_log_notice(const char *m) { SCLogNotice("transport-signals: %s", m); }
void tp_log_error(const char *m)  { SCLogError("transport-signals: %s", m); }

/* ============================================================================
 * Plugin state
 * ========================================================================= */

static bool     g_tp_initialized = false;
static bool     g_tp_tcp_enabled = true;
static bool     g_tp_udp_enabled = true;
static uint32_t g_tp_sample_n    = 1;

/* ============================================================================
 * Helpers
 * ========================================================================= */

static inline int64_t pkt_ts_us(const Packet *p)
{
    return (int64_t)SCTIME_SECS(p->ts) * 1000000 + (int64_t)SCTIME_USECS(p->ts);
}

static void copy_addr(const Packet *p, bool is_src, uint8_t *out, uint32_t *out_len)
{
    if (PacketIsIPv4(p)) {
        const uint32_t *src = is_src
            ? (const uint32_t *)GET_IPV4_SRC_ADDR_PTR(p)
            : (const uint32_t *)GET_IPV4_DST_ADDR_PTR(p);
        char buf[INET_ADDRSTRLEN];
        PrintInet(AF_INET, (const void *)src, buf, sizeof(buf));
        size_t n = strlen(buf);
        if (n > 63) n = 63;
        memcpy(out, buf, n);
        out[n] = '\0';
        *out_len = (uint32_t)n;
    } else if (PacketIsIPv6(p)) {
        const uint32_t *src = is_src
            ? (const uint32_t *)GET_IPV6_SRC_ADDR(p)
            : (const uint32_t *)GET_IPV6_DST_ADDR(p);
        char buf[INET6_ADDRSTRLEN];
        PrintInet(AF_INET6, (const void *)src, buf, sizeof(buf));
        size_t n = strlen(buf);
        if (n > 63) n = 63;
        memcpy(out, buf, n);
        out[n] = '\0';
        *out_len = (uint32_t)n;
    } else {
        out[0] = '\0';
        *out_len = 0;
    }
}

static inline uint8_t pkt_direction(const Packet *p)
{
    if (p->flow == NULL) return 1;
    return PKT_IS_TOSERVER(p) ? 0 : 1;
}

/* ============================================================================
 * Packet logger — updates per-flow state in Rust
 * ========================================================================= */

static bool TpPacketCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    (void)tv; (void)thread_data;
    if (!g_tp_initialized || p == NULL || p->flow == NULL) return false;
    if (PacketIsTCP(p)) return g_tp_tcp_enabled;
    if (PacketIsUDP(p)) return g_tp_udp_enabled;
    return false;
}

static int TpPacketLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    (void)tv; (void)thread_data;
    if (!g_tp_initialized || p == NULL || p->flow == NULL) return 0;

    if (g_tp_sample_n > 1) {
        if ((p->flow->flow_hash % g_tp_sample_n) != 0) return 0;
    }

    Flow *f = p->flow;
    uint64_t flow_hash = f->flow_hash;
    int64_t  ts_us     = pkt_ts_us(p);

    uint8_t  src_ip[64], dst_ip[64];
    uint32_t src_ip_len = 0, dst_ip_len = 0;
    copy_addr(p, true,  src_ip, &src_ip_len);
    copy_addr(p, false, dst_ip, &dst_ip_len);

    uint16_t src_port = p->sp;
    uint16_t dst_port = p->dp;
    uint8_t  dir      = pkt_direction(p);

    if (PacketIsTCP(p)) {
        const TCPHdr *th = PacketGetTCP(p);
        if (th == NULL) return 0;
        rs_tp_observe_tcp(flow_hash, ts_us,
                          src_ip, src_ip_len, dst_ip, dst_ip_len,
                          src_port, dst_port, dir,
                          th->th_flags,
                          TCP_GET_RAW_SEQ(th), TCP_GET_RAW_ACK(th),
                          TCP_GET_RAW_WINDOW(th), 0,
                          p->payload_len);
    } else if (PacketIsUDP(p)) {
        rs_tp_observe_udp(flow_hash, ts_us,
                          src_ip, src_ip_len, dst_ip, dst_ip_len,
                          src_port, dst_port, dir,
                          p->payload_len);
    }
    return 0;
}

/* ============================================================================
 * eve sub-loggers — emit JSON via Suricata's eve writer
 * ========================================================================= */

static void emit_tcp_signal(SCJsonBuilder *jb, const TpTcpStats *s)
{
    SCJbOpenObject(jb, "tcp_signal");
    SCJbSetUint(jb, "start_us",     (uint64_t)s->start_us);
    SCJbSetUint(jb, "end_us",       (uint64_t)s->end_us);
    SCJbSetUint(jb, "duration_us",  (uint64_t)s->duration_us);

    if (s->emit_handshake_rtt && s->has_handshake_rtt) {
        SCJbSetInt(jb, "handshake_rtt_us", s->handshake_rtt_us);
    }
    if (s->has_first_byte_ts) {
        SCJbSetInt(jb, "first_byte_toserver_us", s->first_byte_toserver_us);
    }
    if (s->has_first_byte_tc) {
        SCJbSetInt(jb, "first_byte_toclient_us", s->first_byte_toclient_us);
    }

    /* pkts_toserver/pkts_toclient/bytes_toserver/bytes_toclient are
     * available on the flow event for the same flow_id — no need to
     * duplicate them here. */

    if (s->emit_retransmits) {
        if (s->retransmits_toserver)  SCJbSetUint(jb, "retransmits_toserver",  s->retransmits_toserver);
        if (s->retransmits_toclient)  SCJbSetUint(jb, "retransmits_toclient",  s->retransmits_toclient);
        if (s->out_of_order_toserver) SCJbSetUint(jb, "out_of_order_toserver", s->out_of_order_toserver);
        if (s->out_of_order_toclient) SCJbSetUint(jb, "out_of_order_toclient", s->out_of_order_toclient);
    }
    if (s->emit_zero_window) {
        if (s->zero_window_toserver) SCJbSetUint(jb, "zero_window_toserver", s->zero_window_toserver);
        if (s->zero_window_toclient) SCJbSetUint(jb, "zero_window_toclient", s->zero_window_toclient);
    }
    if (s->rst_count) SCJbSetUint(jb, "rst_count", s->rst_count);
    if (s->fin_count) SCJbSetUint(jb, "fin_count", s->fin_count);

    if (s->emit_window_stats) {
        if (s->has_window_stats_ts) {
            SCJbSetUint(jb, "avg_window_toserver", s->avg_window_toserver);
            SCJbSetUint(jb, "min_window_toserver", s->min_window_toserver);
            SCJbSetUint(jb, "max_window_toserver", s->max_window_toserver);
        }
        if (s->has_window_stats_tc) {
            SCJbSetUint(jb, "avg_window_toclient", s->avg_window_toclient);
            SCJbSetUint(jb, "min_window_toclient", s->min_window_toclient);
            SCJbSetUint(jb, "max_window_toclient", s->max_window_toclient);
        }
    }

    SCJbSetString(jb, "close_reason", (const char *)s->close_reason);
    SCJbClose(jb);   /* tcp_signal */
}

static void emit_udp_signal(SCJsonBuilder *jb, const TpUdpStats *s)
{
    SCJbOpenObject(jb, "udp_signal");
    SCJbSetUint(jb, "start_us",     (uint64_t)s->start_us);
    SCJbSetUint(jb, "end_us",       (uint64_t)s->end_us);
    SCJbSetUint(jb, "duration_us",  (uint64_t)s->duration_us);

    if (s->has_first_byte_ts) {
        SCJbSetInt(jb, "first_byte_toserver_us", s->first_byte_toserver_us);
    }
    if (s->has_first_byte_tc) {
        SCJbSetInt(jb, "first_byte_toclient_us", s->first_byte_toclient_us);
    }

    /* pkts/bytes per direction are on the flow event — join by flow_id. */

    if (s->emit_udp_rtt && s->has_rtt) {
        SCJbSetUint (jb, "rtt_count",  s->rtt_count);
        SCJbSetInt  (jb, "rtt_min_us", s->rtt_min_us);
        SCJbSetInt  (jb, "rtt_max_us", s->rtt_max_us);
        SCJbSetFloat(jb, "rtt_avg_us", s->rtt_avg_us);
        if (s->has_rtt_stddev) {
            SCJbSetFloat(jb, "rtt_stddev_us", s->rtt_stddev_us);
        }
    }
    if (s->emit_udp_jitter) {
        if (s->has_iat_ts)        SCJbSetFloat(jb, "iat_avg_toserver_us",    s->iat_avg_toserver_us);
        if (s->has_iat_tc)        SCJbSetFloat(jb, "iat_avg_toclient_us",    s->iat_avg_toclient_us);
        if (s->has_iat_stddev_ts) SCJbSetFloat(jb, "iat_stddev_toserver_us", s->iat_stddev_toserver_us);
        if (s->has_iat_stddev_tc) SCJbSetFloat(jb, "iat_stddev_toclient_us", s->iat_stddev_toclient_us);
    }
    SCJbClose(jb);   /* udp_signal */
}

static SCJsonBuilder *build_eve_header_for_flow(const Flow *f, const char *event_type)
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
    SCJbSetString(jb, "event_type", event_type);
    SCJbSetString(jb, "src_ip",     srcip);
    SCJbSetUint  (jb, "src_port",   f->sp);
    SCJbSetString(jb, "dest_ip",    dstip);
    SCJbSetUint  (jb, "dest_port",  f->dp);
    SCJbSetString(jb, "proto",      f->proto == IPPROTO_TCP ? "TCP" : "UDP");
    return jb;
}

/* ── TCP flow logger ─────────────────────────────────────────────────── */

static int TpTcpFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    if (!g_tp_initialized || f == NULL || f->proto != IPPROTO_TCP) return 0;

    TpTcpStats stats;
    memset(&stats, 0, sizeof(stats));
    if (!rs_tp_take_tcp_stats(f->flow_hash, &stats) || !stats.valid) return 0;

    OutputJsonThreadCtx *thread = thread_data;
    SCJsonBuilder *jb = build_eve_header_for_flow(f, "tcp_signal");
    if (jb == NULL) return 0;

    emit_tcp_signal(jb, &stats);
    OutputJsonBuilderBuffer(tv, NULL, f, jb, thread);
    SCJbFree(jb);
    return 0;
}

/* ── UDP flow logger ─────────────────────────────────────────────────── */

static int TpUdpFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    if (!g_tp_initialized || f == NULL || f->proto != IPPROTO_UDP) return 0;

    TpUdpStats stats;
    memset(&stats, 0, sizeof(stats));
    if (!rs_tp_take_udp_stats(f->flow_hash, &stats) || !stats.valid) return 0;

    OutputJsonThreadCtx *thread = thread_data;
    SCJsonBuilder *jb = build_eve_header_for_flow(f, "udp_signal");
    if (jb == NULL) return 0;

    emit_udp_signal(jb, &stats);
    OutputJsonBuilderBuffer(tv, NULL, f, jb, thread);
    SCJbFree(jb);
    return 0;
}

/* ============================================================================
 * Thread init/deinit (packet logger only — eve sub-modules use the eve
 * thread init/deinit provided by Suricata)
 * ========================================================================= */

static TmEcode TpPacketThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    (void)tv; (void)initdata;
    *data = NULL;
    return TM_ECODE_OK;
}

static TmEcode TpPacketThreadDeinit(ThreadVars *tv, void *data)
{
    (void)tv; (void)data;
    return TM_ECODE_OK;
}

/* ============================================================================
 * Config bridging — read suricata.yaml and forward to Rust as JSON
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

void RockfishTransportSignalsRegister(void)
{
    int  enabled              = 1;
    int  tcp_enabled          = 1;
    int  udp_enabled          = 1;
    intmax_t sample_n         = 1;
    intmax_t max_flows        = 100000;
    intmax_t flow_idle_secs   = 60;
    intmax_t udp_rtt_window_ms = 2000;
    int  emit_handshake_rtt   = 1;
    int  emit_retransmits     = 1;
    int  emit_zero_window     = 1;
    int  emit_window_stats    = 1;
    int  emit_udp_rtt         = 1;
    int  emit_udp_jitter      = 1;

    SCConfNode *conf = SCConfGetNode("rockfish-transport-signals");
    if (conf != NULL) {
        intmax_t ival;
        int bval;

        if (SCConfGetChildValueBool(conf, "enabled", &bval) == 1) enabled = bval;
        if (SCConfGetChildValueBool(conf, "tcp", &bval) == 1) tcp_enabled = bval;
        if (SCConfGetChildValueBool(conf, "udp", &bval) == 1) udp_enabled = bval;
        if (SCConfGetChildValueInt(conf, "sample-rate", &ival) == 1 && ival > 0) sample_n = ival;
        if (SCConfGetChildValueInt(conf, "max-flows", &ival) == 1 && ival > 0) max_flows = ival;
        if (SCConfGetChildValueInt(conf, "flow-idle-timeout", &ival) == 1 && ival > 0) flow_idle_secs = ival;
        if (SCConfGetChildValueInt(conf, "udp-rtt-pairing-window-ms", &ival) == 1 && ival > 0) udp_rtt_window_ms = ival;

        SCConfNode *emit = SCConfNodeLookupChild(conf, "emit");
        if (emit != NULL) {
            if (SCConfGetChildValueBool(emit, "handshake-rtt", &bval) == 1) emit_handshake_rtt = bval;
            if (SCConfGetChildValueBool(emit, "retransmits", &bval) == 1)   emit_retransmits   = bval;
            if (SCConfGetChildValueBool(emit, "zero-window", &bval) == 1)   emit_zero_window   = bval;
            if (SCConfGetChildValueBool(emit, "window-stats", &bval) == 1)  emit_window_stats  = bval;
            if (SCConfGetChildValueBool(emit, "udp-rtt", &bval) == 1)       emit_udp_rtt       = bval;
            if (SCConfGetChildValueBool(emit, "udp-jitter", &bval) == 1)    emit_udp_jitter    = bval;
        }
    }

    if (!enabled) {
        SCLogNotice("Rockfish Transport Signals disabled by configuration");
        return;
    }
    if (!tcp_enabled && !udp_enabled) {
        SCLogNotice("Rockfish Transport Signals: tcp and udp both disabled — not registering");
        return;
    }

    g_tp_tcp_enabled = (tcp_enabled != 0);
    g_tp_udp_enabled = (udp_enabled != 0);
    g_tp_sample_n    = (uint32_t)sample_n;

    /* Build JSON config for Rust (matches PluginConfig fields). */
    char cfg[1024];
    int  off = 0, first = 1;
    cfg[off++] = '{';
    off = json_bool(cfg, off, sizeof(cfg), &first, "tcp_enabled", tcp_enabled);
    off = json_bool(cfg, off, sizeof(cfg), &first, "udp_enabled", udp_enabled);
    off = json_int (cfg, off, sizeof(cfg), &first, "sample_rate", sample_n);
    off = json_int (cfg, off, sizeof(cfg), &first, "max_flows", max_flows);
    off = json_int (cfg, off, sizeof(cfg), &first, "flow_idle_secs", flow_idle_secs);
    off = json_int (cfg, off, sizeof(cfg), &first, "udp_rtt_window_ms", udp_rtt_window_ms);
    off = json_bool(cfg, off, sizeof(cfg), &first, "emit_handshake_rtt", emit_handshake_rtt);
    off = json_bool(cfg, off, sizeof(cfg), &first, "emit_retransmits", emit_retransmits);
    off = json_bool(cfg, off, sizeof(cfg), &first, "emit_zero_window", emit_zero_window);
    off = json_bool(cfg, off, sizeof(cfg), &first, "emit_window_stats", emit_window_stats);
    off = json_bool(cfg, off, sizeof(cfg), &first, "emit_udp_rtt", emit_udp_rtt);
    off = json_bool(cfg, off, sizeof(cfg), &first, "emit_udp_jitter", emit_udp_jitter);
    if (off < (int)sizeof(cfg) - 2) {
        cfg[off++] = '}';
        cfg[off]   = '\0';
    } else {
        cfg[sizeof(cfg) - 1] = '\0';
    }

    if (rs_tp_init(cfg) != 0) {
        SCLogError("Failed to initialize transport-signals state");
        return;
    }
    g_tp_initialized = true;

    /* ── Packet logger (state updates) ──────────────────────────────── */
    if (SCOutputRegisterPacketLogger(LOGGER_USER, "RockfishTransportSignalsPkt",
                                      TpPacketLogger, TpPacketCondition,
                                      NULL, TpPacketThreadInit, TpPacketThreadDeinit) != 0) {
        SCLogError("Failed to register transport-signals packet logger");
        rs_tp_deinit();
        g_tp_initialized = false;
        return;
    }

    /* ── eve sub-modules: tcp_signal, udp_signal ───────────────────── */
    if (tcp_enabled) {
        OutputRegisterFlowSubModule(LOGGER_USER, "eve-log",
            "RockfishTcpSignalLog", "eve-log.tcp_signal",
            OutputJsonLogInitSub, TpTcpFlowLogger,
            JsonLogThreadInit, JsonLogThreadDeinit);
    }
    if (udp_enabled) {
        OutputRegisterFlowSubModule(LOGGER_USER, "eve-log",
            "RockfishUdpSignalLog", "eve-log.udp_signal",
            OutputJsonLogInitSub, TpUdpFlowLogger,
            JsonLogThreadInit, JsonLogThreadDeinit);
    }

    /* ── Startup banner ────────────────────────────────────────────── */
    SCLogNotice("════════════════════════════════════════════════════════════");
    SCLogNotice("  Rockfish Transport Signals v%s — LOADED",
                ROCKFISH_TRANSPORT_SIGNALS_VERSION);
    SCLogNotice("    TCP:               %s", tcp_enabled ? "enabled" : "disabled");
    SCLogNotice("    UDP:               %s", udp_enabled ? "enabled" : "disabled");
    SCLogNotice("    Sample rate:       1/%u", (unsigned)sample_n);
    SCLogNotice("    Max flows:         %jd", max_flows);
    SCLogNotice("    Flow idle timeout: %jds", flow_idle_secs);
    SCLogNotice("    UDP RTT window:    %jdms", udp_rtt_window_ms);
    SCLogNotice("    Emit:              handshake_rtt=%s retransmits=%s zero_window=%s",
                emit_handshake_rtt ? "yes" : "no",
                emit_retransmits   ? "yes" : "no",
                emit_zero_window   ? "yes" : "no");
    SCLogNotice("                       window_stats=%s udp_rtt=%s udp_jitter=%s",
                emit_window_stats  ? "yes" : "no",
                emit_udp_rtt       ? "yes" : "no",
                emit_udp_jitter    ? "yes" : "no");
    SCLogNotice("    Events:            %s%s%s%s",
                tcp_enabled ? "tcp_signal" : "",
                tcp_enabled && udp_enabled ? ", " : "",
                udp_enabled ? "udp_signal" : "",
                (!tcp_enabled && !udp_enabled) ? "(none — both disabled)" : "");
    SCLogNotice("    Output:            via eve-log (add types to your eve-log.types list)");
    SCLogNotice("════════════════════════════════════════════════════════════");
}
