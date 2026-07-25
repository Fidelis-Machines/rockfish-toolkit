/* Fidelis Farm & Technologies, LLC LwM2M Parser — Suricata App-Layer Registration
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

#include "lwm2m-plugin.h"

/* Rust FFI */
extern int rs_lwm2m_probe(const uint8_t *buf, uint32_t len);
extern void *rs_lwm2m_state_new(void);
extern void rs_lwm2m_state_free(void *state);
extern int rs_lwm2m_parse(void *state, const uint8_t *buf, uint32_t len);
extern uint64_t rs_lwm2m_get_tx_count(const void *state);
extern const void *rs_lwm2m_get_tx(const void *state, uint64_t tx_index);
extern void rs_lwm2m_tx_free(void *state, uint64_t tx_id);

/* Logging helpers */
void lwm2m_log_notice(const char *msg) { SCLogNotice("lwm2m: %s", msg); }
void lwm2m_log_error(const char *msg)  { SCLogError("lwm2m: %s", msg); }

/* C-side wrappers for Suricata bookkeeping */
typedef struct Lwm2mTx_ {
    AppLayerTxData tx_data;
    const void *rs_tx;
    uint64_t tx_id;
} Lwm2mTx;

typedef struct Lwm2mState_ {
    AppLayerStateData state_data;
    void *rs_state;
    Lwm2mTx **txs;
    uint64_t tx_count;
    uint64_t tx_alloc;
} Lwm2mState;

/* Callbacks */
static AppProto ALPROTO_Lwm2m = ALPROTO_UNKNOWN;

static AppProto Lwm2mProbe(
    const Flow *f, uint8_t direction, const uint8_t *buf, uint32_t len,
    uint8_t *rdir)
{
    (void)f; (void)direction; (void)rdir;
    if (rs_lwm2m_probe(buf, len)) return ALPROTO_Lwm2m;
    return ALPROTO_UNKNOWN;
}

static void *Lwm2mStateAlloc(void *orig, AppProto p)
{
    (void)orig; (void)p;
    Lwm2mState *s = calloc(1, sizeof(Lwm2mState));
    if (!s) return NULL;
    s->rs_state = rs_lwm2m_state_new();
    s->tx_alloc = 16;
    s->txs = calloc(s->tx_alloc, sizeof(Lwm2mTx *));
    return s;
}

static void Lwm2mStateFree(void *vstate)
{
    Lwm2mState *s = (Lwm2mState *)vstate;
    if (!s) return;
    for (uint64_t i = 0; i < s->tx_count; i++) {
        if (s->txs[i]) free(s->txs[i]);
    }
    free(s->txs);
    rs_lwm2m_state_free(s->rs_state);
    free(s);
}

static AppLayerResult Lwm2mParseTS(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    (void)f; (void)pstate; (void)ld;
    Lwm2mState *s = (Lwm2mState *)vstate;
    const uint8_t *buf = StreamSliceGetData(&ss);
    uint32_t len = StreamSliceGetDataLen(&ss);
    if (!buf || len == 0) return APP_LAYER_OK;

    int ret = rs_lwm2m_parse(s->rs_state, buf, len);
    if (ret < 0) return APP_LAYER_ERROR;

    /* Sync C-side tx list with Rust tx count */
    uint64_t rust_count = rs_lwm2m_get_tx_count(s->rs_state);
    while (s->tx_count < rust_count) {
        if (s->tx_count >= s->tx_alloc) {
            s->tx_alloc *= 2;
            s->txs = realloc(s->txs, s->tx_alloc * sizeof(Lwm2mTx *));
        }
        Lwm2mTx *tx = calloc(1, sizeof(Lwm2mTx));
        if (!tx) return APP_LAYER_ERROR;
        tx->tx_id = s->tx_count;
        tx->rs_tx = rs_lwm2m_get_tx(s->rs_state, s->tx_count);
        tx->tx_data.updated_ts = true;
        s->txs[s->tx_count] = tx;
        s->tx_count++;
    }
    return APP_LAYER_OK;
}

static AppLayerResult Lwm2mParseTC(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    return Lwm2mParseTS(f, vstate, pstate, ss, ld);
}

static uint64_t Lwm2mGetTxCnt(void *vstate)
{
    return ((Lwm2mState *)vstate)->tx_count;
}

static void *Lwm2mGetTx(void *vstate, uint64_t tx_id)
{
    Lwm2mState *s = (Lwm2mState *)vstate;
    if (tx_id < s->tx_count) return s->txs[tx_id];
    return NULL;
}

static int Lwm2mGetProgress(void *vtx, uint8_t dir)
{
    (void)vtx; (void)dir;
    return 1;
}

static void Lwm2mTxFree(void *vstate, uint64_t tx_id)
{
    Lwm2mState *s = (Lwm2mState *)vstate;
    if (tx_id < s->tx_count && s->txs[tx_id]) {
        rs_lwm2m_tx_free(s->rs_state, tx_id);
        free(s->txs[tx_id]);
        s->txs[tx_id] = NULL;
    }
}

static AppLayerTxData *Lwm2mGetTxData(void *vtx)
{
    return &((Lwm2mTx *)vtx)->tx_data;
}

static AppLayerStateData *Lwm2mGetStateData(void *vstate)
{
    return &((Lwm2mState *)vstate)->state_data;
}

/* Registration */
void Lwm2mParserRegister(void)
{
    SCLogNotice("Registering LwM2M application-layer parser");

    AppLayerParser parser = {
        .name              = "lwm2m",
        .default_port      = "[5683]",
        .ip_proto          = IPPROTO_UDP,
        .ProbeTS           = Lwm2mProbe,
        .ProbeTC           = Lwm2mProbe,
        .min_depth         = 0,
        .max_depth         = 16,
        .StateAlloc        = Lwm2mStateAlloc,
        .StateFree         = Lwm2mStateFree,
        .ParseTS           = Lwm2mParseTS,
        .ParseTC           = Lwm2mParseTC,
        .StateGetTxCnt     = Lwm2mGetTxCnt,
        .StateGetTx        = Lwm2mGetTx,
        .StateTransactionFree = Lwm2mTxFree,
        .complete_ts       = 1,
        .complete_tc       = 1,
        .StateGetProgress  = Lwm2mGetProgress,
        .GetTxData         = Lwm2mGetTxData,
        .GetStateData      = Lwm2mGetStateData,
        .flags             = 0,
    };

    ALPROTO_Lwm2m = AppLayerRegisterProtocolDetection(&parser, 1);
    if (ALPROTO_Lwm2m == ALPROTO_UNKNOWN) {
        SCLogError("Failed to register LwM2M protocol detection");
        return;
    }
    AppLayerRegisterParser(&parser, ALPROTO_Lwm2m);
    SCLogNotice("lwm2m parser registered (ALPROTO=%d)", ALPROTO_Lwm2m);
}
