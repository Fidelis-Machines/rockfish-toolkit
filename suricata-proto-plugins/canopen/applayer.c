/* Fidelis Farm & Technologies, LLC CANopen Parser — Suricata App-Layer Registration
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

#include "canopen-plugin.h"

/* Rust FFI */
extern int rs_canopen_probe(const uint8_t *buf, uint32_t len);
extern void *rs_canopen_state_new(void);
extern void rs_canopen_state_free(void *state);
extern int rs_canopen_parse(void *state, const uint8_t *buf, uint32_t len);
extern uint64_t rs_canopen_get_tx_count(const void *state);
extern const void *rs_canopen_get_tx(const void *state, uint64_t tx_index);
extern void rs_canopen_tx_free(void *state, uint64_t tx_id);

/* Logging helpers */
void canopen_log_notice(const char *msg) { SCLogNotice("canopen: %s", msg); }
void canopen_log_error(const char *msg)  { SCLogError("canopen: %s", msg); }

/* C-side wrappers for Suricata bookkeeping */
typedef struct CanopenTx_ {
    AppLayerTxData tx_data;
    const void *rs_tx;
    uint64_t tx_id;
} CanopenTx;

typedef struct CanopenState_ {
    AppLayerStateData state_data;
    void *rs_state;
    CanopenTx **txs;
    uint64_t tx_count;
    uint64_t tx_alloc;
} CanopenState;

/* Callbacks */
static AppProto ALPROTO_Canopen = ALPROTO_UNKNOWN;

static AppProto CanopenProbe(
    const Flow *f, uint8_t direction, const uint8_t *buf, uint32_t len,
    uint8_t *rdir)
{
    (void)f; (void)direction; (void)rdir;
    if (rs_canopen_probe(buf, len)) return ALPROTO_Canopen;
    return ALPROTO_UNKNOWN;
}

static void *CanopenStateAlloc(void *orig, AppProto p)
{
    (void)orig; (void)p;
    CanopenState *s = calloc(1, sizeof(CanopenState));
    if (!s) return NULL;
    s->rs_state = rs_canopen_state_new();
    s->tx_alloc = 16;
    s->txs = calloc(s->tx_alloc, sizeof(CanopenTx *));
    return s;
}

static void CanopenStateFree(void *vstate)
{
    CanopenState *s = (CanopenState *)vstate;
    if (!s) return;
    for (uint64_t i = 0; i < s->tx_count; i++) {
        if (s->txs[i]) free(s->txs[i]);
    }
    free(s->txs);
    rs_canopen_state_free(s->rs_state);
    free(s);
}

static AppLayerResult CanopenParseTS(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    (void)f; (void)pstate; (void)ld;
    CanopenState *s = (CanopenState *)vstate;
    const uint8_t *buf = StreamSliceGetData(&ss);
    uint32_t len = StreamSliceGetDataLen(&ss);
    if (!buf || len == 0) return APP_LAYER_OK;

    int ret = rs_canopen_parse(s->rs_state, buf, len);
    if (ret < 0) return APP_LAYER_ERROR;

    /* Sync C-side tx list with Rust tx count */
    uint64_t rust_count = rs_canopen_get_tx_count(s->rs_state);
    while (s->tx_count < rust_count) {
        if (s->tx_count >= s->tx_alloc) {
            s->tx_alloc *= 2;
            s->txs = realloc(s->txs, s->tx_alloc * sizeof(CanopenTx *));
        }
        CanopenTx *tx = calloc(1, sizeof(CanopenTx));
        if (!tx) return APP_LAYER_ERROR;
        tx->tx_id = s->tx_count;
        tx->rs_tx = rs_canopen_get_tx(s->rs_state, s->tx_count);
        tx->tx_data.updated_ts = true;
        s->txs[s->tx_count] = tx;
        s->tx_count++;
    }
    return APP_LAYER_OK;
}

static AppLayerResult CanopenParseTC(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    return CanopenParseTS(f, vstate, pstate, ss, ld);
}

static uint64_t CanopenGetTxCnt(void *vstate)
{
    return ((CanopenState *)vstate)->tx_count;
}

static void *CanopenGetTx(void *vstate, uint64_t tx_id)
{
    CanopenState *s = (CanopenState *)vstate;
    if (tx_id < s->tx_count) return s->txs[tx_id];
    return NULL;
}

static int CanopenGetProgress(void *vtx, uint8_t dir)
{
    (void)vtx; (void)dir;
    return 1;
}

static void CanopenTxFree(void *vstate, uint64_t tx_id)
{
    CanopenState *s = (CanopenState *)vstate;
    if (tx_id < s->tx_count && s->txs[tx_id]) {
        rs_canopen_tx_free(s->rs_state, tx_id);
        free(s->txs[tx_id]);
        s->txs[tx_id] = NULL;
    }
}

static AppLayerTxData *CanopenGetTxData(void *vtx)
{
    return &((CanopenTx *)vtx)->tx_data;
}

static AppLayerStateData *CanopenGetStateData(void *vstate)
{
    return &((CanopenState *)vstate)->state_data;
}

/* Registration */
void CanopenParserRegister(void)
{
    SCLogNotice("Registering CANopen application-layer parser");

    AppLayerParser parser = {
        .name              = "canopen",
        .default_port      = "[0]",
        .ip_proto          = IPPROTO_UDP,
        .ProbeTS           = CanopenProbe,
        .ProbeTC           = CanopenProbe,
        .min_depth         = 0,
        .max_depth         = 16,
        .StateAlloc        = CanopenStateAlloc,
        .StateFree         = CanopenStateFree,
        .ParseTS           = CanopenParseTS,
        .ParseTC           = CanopenParseTC,
        .StateGetTxCnt     = CanopenGetTxCnt,
        .StateGetTx        = CanopenGetTx,
        .StateTransactionFree = CanopenTxFree,
        .complete_ts       = 1,
        .complete_tc       = 1,
        .StateGetProgress  = CanopenGetProgress,
        .GetTxData         = CanopenGetTxData,
        .GetStateData      = CanopenGetStateData,
        .flags             = 0,
    };

    ALPROTO_Canopen = AppLayerRegisterProtocolDetection(&parser, 1);
    if (ALPROTO_Canopen == ALPROTO_UNKNOWN) {
        SCLogError("Failed to register CANopen protocol detection");
        return;
    }
    AppLayerRegisterParser(&parser, ALPROTO_Canopen);
    SCLogNotice("canopen parser registered (ALPROTO=%d)", ALPROTO_Canopen);
}
