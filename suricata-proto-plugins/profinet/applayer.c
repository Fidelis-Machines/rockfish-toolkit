/* Fidelis Farm & Technologies, LLC PROFINET DCP Parser — Suricata App-Layer Registration
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Uses C-side wrappers with AppLayerTxData/AppLayerStateData for Suricata 8+.
 */

#include "suricata-common.h"
#include "suricata-plugin.h"
#include "util-debug.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"
#include "app-layer-register.h"

#include "profinet-plugin.h"

/* Rust FFI */
extern int rs_profinet_probe(const uint8_t *buf, uint32_t len);
extern void *rs_profinet_state_new(void);
extern void rs_profinet_state_free(void *state);
extern int rs_profinet_parse(void *state, const uint8_t *buf, uint32_t len);
extern uint64_t rs_profinet_get_tx_count(const void *state);
extern const void *rs_profinet_get_tx(const void *state, uint64_t tx_index);
extern void rs_profinet_tx_free(void *state, uint64_t tx_id);

/* Logging helpers */
void profinet_log_notice(const char *msg) { SCLogNotice("profinet: %s", msg); }
void profinet_log_error(const char *msg)  { SCLogError("profinet: %s", msg); }

/* C-side wrappers for Suricata bookkeeping */
typedef struct ProfinetTx_ {
    AppLayerTxData tx_data;
    const void *rs_tx;
    uint64_t tx_id;
} ProfinetTx;

typedef struct ProfinetState_ {
    AppLayerStateData state_data;
    void *rs_state;
    ProfinetTx **txs;
    uint64_t tx_count;
    uint64_t tx_alloc;
} ProfinetState;

/* Callbacks */
static AppProto ALPROTO_Profinet = ALPROTO_UNKNOWN;

static AppProto ProfinetProbe(
    const Flow *f, uint8_t direction, const uint8_t *buf, uint32_t len,
    uint8_t *rdir)
{
    (void)f; (void)direction; (void)rdir;
    if (rs_profinet_probe(buf, len)) return ALPROTO_Profinet;
    return ALPROTO_UNKNOWN;
}

static void *ProfinetStateAlloc(void *orig, AppProto p)
{
    (void)orig; (void)p;
    ProfinetState *s = calloc(1, sizeof(ProfinetState));
    if (!s) return NULL;
    s->rs_state = rs_profinet_state_new();
    s->tx_alloc = 16;
    s->txs = calloc(s->tx_alloc, sizeof(ProfinetTx *));
    return s;
}

static void ProfinetStateFree(void *vstate)
{
    ProfinetState *s = (ProfinetState *)vstate;
    if (!s) return;
    for (uint64_t i = 0; i < s->tx_count; i++) {
        if (s->txs[i]) free(s->txs[i]);
    }
    free(s->txs);
    rs_profinet_state_free(s->rs_state);
    free(s);
}

static AppLayerResult ProfinetParseTS(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    (void)f; (void)pstate; (void)ld;
    ProfinetState *s = (ProfinetState *)vstate;
    const uint8_t *buf = StreamSliceGetData(&ss);
    uint32_t len = StreamSliceGetDataLen(&ss);
    if (!buf || len == 0) return APP_LAYER_OK;

    int ret = rs_profinet_parse(s->rs_state, buf, len);
    if (ret < 0) return APP_LAYER_ERROR;

    /* Sync C-side tx list with Rust tx count */
    uint64_t rust_count = rs_profinet_get_tx_count(s->rs_state);
    while (s->tx_count < rust_count) {
        if (s->tx_count >= s->tx_alloc) {
            s->tx_alloc *= 2;
            s->txs = realloc(s->txs, s->tx_alloc * sizeof(ProfinetTx *));
        }
        ProfinetTx *tx = calloc(1, sizeof(ProfinetTx));
        if (!tx) return APP_LAYER_ERROR;
        tx->tx_id = s->tx_count;
        tx->rs_tx = rs_profinet_get_tx(s->rs_state, s->tx_count);
        tx->tx_data.updated_ts = true;
        s->txs[s->tx_count] = tx;
        s->tx_count++;
    }
    return APP_LAYER_OK;
}

static AppLayerResult ProfinetParseTC(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    return ProfinetParseTS(f, vstate, pstate, ss, ld);
}

static uint64_t ProfinetGetTxCnt(void *vstate)
{
    return ((ProfinetState *)vstate)->tx_count;
}

static void *ProfinetGetTx(void *vstate, uint64_t tx_id)
{
    ProfinetState *s = (ProfinetState *)vstate;
    if (tx_id < s->tx_count) return s->txs[tx_id];
    return NULL;
}

static int ProfinetGetProgress(void *vtx, uint8_t dir)
{
    (void)vtx; (void)dir;
    return 1;
}

static void ProfinetTxFree(void *vstate, uint64_t tx_id)
{
    ProfinetState *s = (ProfinetState *)vstate;
    if (tx_id < s->tx_count && s->txs[tx_id]) {
        rs_profinet_tx_free(s->rs_state, tx_id);
        free(s->txs[tx_id]);
        s->txs[tx_id] = NULL;
    }
}

static AppLayerTxData *ProfinetGetTxData(void *vtx)
{
    return &((ProfinetTx *)vtx)->tx_data;
}

static AppLayerStateData *ProfinetGetStateData(void *vstate)
{
    return &((ProfinetState *)vstate)->state_data;
}

/* Registration */
void ProfinetParserRegister(void)
{
    SCLogNotice("Registering PROFINET DCP application-layer parser");

    AppLayerParser parser = {
        .name              = "profinet",
        .default_port      = "[34964]",
        .ip_proto          = IPPROTO_UDP,
        .ProbeTS           = ProfinetProbe,
        .ProbeTC           = ProfinetProbe,
        .min_depth         = 0,
        .max_depth         = 16,
        .StateAlloc        = ProfinetStateAlloc,
        .StateFree         = ProfinetStateFree,
        .ParseTS           = ProfinetParseTS,
        .ParseTC           = ProfinetParseTC,
        .StateGetTxCnt     = ProfinetGetTxCnt,
        .StateGetTx        = ProfinetGetTx,
        .StateTransactionFree = ProfinetTxFree,
        .complete_ts       = 1,
        .complete_tc       = 1,
        .StateGetProgress  = ProfinetGetProgress,
        .GetTxData         = ProfinetGetTxData,
        .GetStateData      = ProfinetGetStateData,
        .flags             = 0,
    };

    ALPROTO_Profinet = AppLayerRegisterProtocolDetection(&parser, 1);
    if (ALPROTO_Profinet == ALPROTO_UNKNOWN) {
        SCLogError("Failed to register PROFINET DCP protocol detection");
        return;
    }
    AppLayerRegisterParser(&parser, ALPROTO_Profinet);
    SCLogNotice("profinet parser registered (ALPROTO=%d)", ALPROTO_Profinet);
}
