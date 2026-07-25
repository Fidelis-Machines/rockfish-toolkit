/* Fidelis Farm & Technologies, LLC Siemens S7comm Parser — Suricata App-Layer Registration
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

#include "s7comm-plugin.h"

/* Rust FFI */
extern int rs_s7comm_probe(const uint8_t *buf, uint32_t len);
extern void *rs_s7comm_state_new(void);
extern void rs_s7comm_state_free(void *state);
extern int rs_s7comm_parse(void *state, const uint8_t *buf, uint32_t len);
extern uint64_t rs_s7comm_get_tx_count(const void *state);
extern const void *rs_s7comm_get_tx(const void *state, uint64_t tx_index);
extern void rs_s7comm_tx_free(void *state, uint64_t tx_id);

/* Logging helpers */
void s7comm_log_notice(const char *msg) { SCLogNotice("s7comm: %s", msg); }
void s7comm_log_error(const char *msg)  { SCLogError("s7comm: %s", msg); }

/* C-side wrappers for Suricata bookkeeping */
typedef struct S7commTx_ {
    AppLayerTxData tx_data;
    const void *rs_tx;
    uint64_t tx_id;
} S7commTx;

typedef struct S7commState_ {
    AppLayerStateData state_data;
    void *rs_state;
    S7commTx **txs;
    uint64_t tx_count;
    uint64_t tx_alloc;
} S7commState;

/* Callbacks */
static AppProto ALPROTO_S7comm = ALPROTO_UNKNOWN;

static AppProto S7commProbe(
    const Flow *f, uint8_t direction, const uint8_t *buf, uint32_t len,
    uint8_t *rdir)
{
    (void)f; (void)direction; (void)rdir;
    if (rs_s7comm_probe(buf, len)) return ALPROTO_S7comm;
    return ALPROTO_UNKNOWN;
}

static void *S7commStateAlloc(void *orig, AppProto p)
{
    (void)orig; (void)p;
    S7commState *s = calloc(1, sizeof(S7commState));
    if (!s) return NULL;
    s->rs_state = rs_s7comm_state_new();
    s->tx_alloc = 16;
    s->txs = calloc(s->tx_alloc, sizeof(S7commTx *));
    return s;
}

static void S7commStateFree(void *vstate)
{
    S7commState *s = (S7commState *)vstate;
    if (!s) return;
    for (uint64_t i = 0; i < s->tx_count; i++) {
        if (s->txs[i]) free(s->txs[i]);
    }
    free(s->txs);
    rs_s7comm_state_free(s->rs_state);
    free(s);
}

static AppLayerResult S7commParseTS(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    (void)f; (void)pstate; (void)ld;
    S7commState *s = (S7commState *)vstate;
    const uint8_t *buf = StreamSliceGetData(&ss);
    uint32_t len = StreamSliceGetDataLen(&ss);
    if (!buf || len == 0) return APP_LAYER_OK;

    int ret = rs_s7comm_parse(s->rs_state, buf, len);
    if (ret < 0) return APP_LAYER_ERROR;

    /* Sync C-side tx list with Rust tx count */
    uint64_t rust_count = rs_s7comm_get_tx_count(s->rs_state);
    while (s->tx_count < rust_count) {
        if (s->tx_count >= s->tx_alloc) {
            s->tx_alloc *= 2;
            s->txs = realloc(s->txs, s->tx_alloc * sizeof(S7commTx *));
        }
        S7commTx *tx = calloc(1, sizeof(S7commTx));
        if (!tx) return APP_LAYER_ERROR;
        tx->tx_id = s->tx_count;
        tx->rs_tx = rs_s7comm_get_tx(s->rs_state, s->tx_count);
        tx->tx_data.updated_ts = true;
        s->txs[s->tx_count] = tx;
        s->tx_count++;
    }
    return APP_LAYER_OK;
}

static AppLayerResult S7commParseTC(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    return S7commParseTS(f, vstate, pstate, ss, ld);
}

static uint64_t S7commGetTxCnt(void *vstate)
{
    return ((S7commState *)vstate)->tx_count;
}

static void *S7commGetTx(void *vstate, uint64_t tx_id)
{
    S7commState *s = (S7commState *)vstate;
    if (tx_id < s->tx_count) return s->txs[tx_id];
    return NULL;
}

static int S7commGetProgress(void *vtx, uint8_t dir)
{
    (void)vtx; (void)dir;
    return 1;
}

static void S7commTxFree(void *vstate, uint64_t tx_id)
{
    S7commState *s = (S7commState *)vstate;
    if (tx_id < s->tx_count && s->txs[tx_id]) {
        rs_s7comm_tx_free(s->rs_state, tx_id);
        free(s->txs[tx_id]);
        s->txs[tx_id] = NULL;
    }
}

static AppLayerTxData *S7commGetTxData(void *vtx)
{
    return &((S7commTx *)vtx)->tx_data;
}

static AppLayerStateData *S7commGetStateData(void *vstate)
{
    return &((S7commState *)vstate)->state_data;
}

/* Registration */
void S7commParserRegister(void)
{
    SCLogNotice("Registering Siemens S7comm application-layer parser");

    AppLayerParser parser = {
        .name              = "s7comm",
        .default_port      = "[102]",
        .ip_proto          = IPPROTO_TCP,
        .ProbeTS           = S7commProbe,
        .ProbeTC           = S7commProbe,
        .min_depth         = 0,
        .max_depth         = 8,
        .StateAlloc        = S7commStateAlloc,
        .StateFree         = S7commStateFree,
        .ParseTS           = S7commParseTS,
        .ParseTC           = S7commParseTC,
        .StateGetTxCnt     = S7commGetTxCnt,
        .StateGetTx        = S7commGetTx,
        .StateTransactionFree = S7commTxFree,
        .complete_ts       = 1,
        .complete_tc       = 1,
        .StateGetProgress  = S7commGetProgress,
        .GetTxData         = S7commGetTxData,
        .GetStateData      = S7commGetStateData,
        .flags             = 0,
    };

    ALPROTO_S7comm = AppLayerRegisterProtocolDetection(&parser, 1);
    if (ALPROTO_S7comm == ALPROTO_UNKNOWN) {
        SCLogError("Failed to register Siemens S7comm protocol detection");
        return;
    }
    AppLayerRegisterParser(&parser, ALPROTO_S7comm);
    SCLogNotice("s7comm parser registered (ALPROTO=%d)", ALPROTO_S7comm);
}
