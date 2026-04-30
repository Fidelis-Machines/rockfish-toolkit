/* Fidelis Farm & Technologies, LLC CoAP Parser — Suricata App-Layer Registration
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

#include "coap-plugin.h"

/* Rust FFI */
extern int rs_coap_probe(const uint8_t *buf, uint32_t len);
extern void *rs_coap_state_new(void);
extern void rs_coap_state_free(void *state);
extern int rs_coap_parse(void *state, const uint8_t *buf, uint32_t len);
extern uint64_t rs_coap_get_tx_count(const void *state);
extern const void *rs_coap_get_tx(const void *state, uint64_t tx_index);
extern void rs_coap_tx_free(void *state, uint64_t tx_id);

/* Logging helpers */
void coap_log_notice(const char *msg) { SCLogNotice("coap: %s", msg); }
void coap_log_error(const char *msg)  { SCLogError("coap: %s", msg); }

/* C-side wrappers for Suricata bookkeeping */
typedef struct CoapTx_ {
    AppLayerTxData tx_data;
    const void *rs_tx;
    uint64_t tx_id;
} CoapTx;

typedef struct CoapState_ {
    AppLayerStateData state_data;
    void *rs_state;
    CoapTx **txs;
    uint64_t tx_count;
    uint64_t tx_alloc;
} CoapState;

/* Callbacks */
static AppProto ALPROTO_Coap = ALPROTO_UNKNOWN;

static AppProto CoapProbe(
    const Flow *f, uint8_t direction, const uint8_t *buf, uint32_t len,
    uint8_t *rdir)
{
    (void)f; (void)direction; (void)rdir;
    if (rs_coap_probe(buf, len)) return ALPROTO_Coap;
    return ALPROTO_UNKNOWN;
}

static void *CoapStateAlloc(void *orig, AppProto p)
{
    (void)orig; (void)p;
    CoapState *s = calloc(1, sizeof(CoapState));
    if (!s) return NULL;
    s->rs_state = rs_coap_state_new();
    s->tx_alloc = 16;
    s->txs = calloc(s->tx_alloc, sizeof(CoapTx *));
    return s;
}

static void CoapStateFree(void *vstate)
{
    CoapState *s = (CoapState *)vstate;
    if (!s) return;
    for (uint64_t i = 0; i < s->tx_count; i++) {
        if (s->txs[i]) free(s->txs[i]);
    }
    free(s->txs);
    rs_coap_state_free(s->rs_state);
    free(s);
}

static AppLayerResult CoapParseTS(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    (void)f; (void)pstate; (void)ld;
    CoapState *s = (CoapState *)vstate;
    const uint8_t *buf = StreamSliceGetData(&ss);
    uint32_t len = StreamSliceGetDataLen(&ss);
    if (!buf || len == 0) return APP_LAYER_OK;

    int ret = rs_coap_parse(s->rs_state, buf, len);
    if (ret < 0) return APP_LAYER_ERROR;

    /* Sync C-side tx list with Rust tx count */
    uint64_t rust_count = rs_coap_get_tx_count(s->rs_state);
    while (s->tx_count < rust_count) {
        if (s->tx_count >= s->tx_alloc) {
            s->tx_alloc *= 2;
            s->txs = realloc(s->txs, s->tx_alloc * sizeof(CoapTx *));
        }
        CoapTx *tx = calloc(1, sizeof(CoapTx));
        if (!tx) return APP_LAYER_ERROR;
        tx->tx_id = s->tx_count;
        tx->rs_tx = rs_coap_get_tx(s->rs_state, s->tx_count);
        tx->tx_data.updated_ts = true;
        s->txs[s->tx_count] = tx;
        s->tx_count++;
    }
    return APP_LAYER_OK;
}

static AppLayerResult CoapParseTC(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    return CoapParseTS(f, vstate, pstate, ss, ld);
}

static uint64_t CoapGetTxCnt(void *vstate)
{
    return ((CoapState *)vstate)->tx_count;
}

static void *CoapGetTx(void *vstate, uint64_t tx_id)
{
    CoapState *s = (CoapState *)vstate;
    if (tx_id < s->tx_count) return s->txs[tx_id];
    return NULL;
}

static int CoapGetProgress(void *vtx, uint8_t dir)
{
    (void)vtx; (void)dir;
    return 1;
}

static void CoapTxFree(void *vstate, uint64_t tx_id)
{
    CoapState *s = (CoapState *)vstate;
    if (tx_id < s->tx_count && s->txs[tx_id]) {
        rs_coap_tx_free(s->rs_state, tx_id);
        free(s->txs[tx_id]);
        s->txs[tx_id] = NULL;
    }
}

static AppLayerTxData *CoapGetTxData(void *vtx)
{
    return &((CoapTx *)vtx)->tx_data;
}

static AppLayerStateData *CoapGetStateData(void *vstate)
{
    return &((CoapState *)vstate)->state_data;
}

/* Registration */
void CoapParserRegister(void)
{
    SCLogNotice("Registering CoAP application-layer parser");

    AppLayerParser parser = {
        .name              = "coap",
        .default_port      = "[5683]",
        .ip_proto          = IPPROTO_UDP,
        .ProbeTS           = CoapProbe,
        .ProbeTC           = CoapProbe,
        .min_depth         = 0,
        .max_depth         = 4,
        .StateAlloc        = CoapStateAlloc,
        .StateFree         = CoapStateFree,
        .ParseTS           = CoapParseTS,
        .ParseTC           = CoapParseTC,
        .StateGetTxCnt     = CoapGetTxCnt,
        .StateGetTx        = CoapGetTx,
        .StateTransactionFree = CoapTxFree,
        .complete_ts       = 1,
        .complete_tc       = 1,
        .StateGetProgress  = CoapGetProgress,
        .GetTxData         = CoapGetTxData,
        .GetStateData      = CoapGetStateData,
        .flags             = 0,
    };

    ALPROTO_Coap = AppLayerRegisterProtocolDetection(&parser, 1);
    if (ALPROTO_Coap == ALPROTO_UNKNOWN) {
        SCLogError("Failed to register CoAP protocol detection");
        return;
    }
    AppLayerRegisterParser(&parser, ALPROTO_Coap);
    SCLogNotice("coap parser registered (ALPROTO=%d)", ALPROTO_Coap);
}
