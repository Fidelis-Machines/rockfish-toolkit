/* Fidelis Farm & Technologies, LLC BACnet Parser — Suricata App-Layer Registration
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

#include "bacnet-plugin.h"

/* Rust FFI */
extern int rs_bacnet_probe(const uint8_t *buf, uint32_t len);
extern void *rs_bacnet_state_new(void);
extern void rs_bacnet_state_free(void *state);
extern int rs_bacnet_parse(void *state, const uint8_t *buf, uint32_t len);
extern uint64_t rs_bacnet_get_tx_count(const void *state);
extern const void *rs_bacnet_get_tx(const void *state, uint64_t tx_index);
extern void rs_bacnet_tx_free(void *state, uint64_t tx_id);

/* Logging helpers */
void bacnet_log_notice(const char *msg) { SCLogNotice("bacnet: %s", msg); }
void bacnet_log_error(const char *msg)  { SCLogError("bacnet: %s", msg); }

/* C-side wrappers for Suricata bookkeeping */
typedef struct BacnetTx_ {
    AppLayerTxData tx_data;
    const void *rs_tx;
    uint64_t tx_id;
} BacnetTx;

typedef struct BacnetState_ {
    AppLayerStateData state_data;
    void *rs_state;
    BacnetTx **txs;
    uint64_t tx_count;
    uint64_t tx_alloc;
} BacnetState;

/* Callbacks */
static AppProto ALPROTO_Bacnet = ALPROTO_UNKNOWN;

static AppProto BacnetProbe(
    const Flow *f, uint8_t direction, const uint8_t *buf, uint32_t len,
    uint8_t *rdir)
{
    (void)f; (void)direction; (void)rdir;
    if (rs_bacnet_probe(buf, len)) return ALPROTO_Bacnet;
    return ALPROTO_UNKNOWN;
}

static void *BacnetStateAlloc(void *orig, AppProto p)
{
    (void)orig; (void)p;
    BacnetState *s = calloc(1, sizeof(BacnetState));
    if (!s) return NULL;
    s->rs_state = rs_bacnet_state_new();
    s->tx_alloc = 16;
    s->txs = calloc(s->tx_alloc, sizeof(BacnetTx *));
    return s;
}

static void BacnetStateFree(void *vstate)
{
    BacnetState *s = (BacnetState *)vstate;
    if (!s) return;
    for (uint64_t i = 0; i < s->tx_count; i++) {
        if (s->txs[i]) free(s->txs[i]);
    }
    free(s->txs);
    rs_bacnet_state_free(s->rs_state);
    free(s);
}

static AppLayerResult BacnetParseTS(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    (void)f; (void)pstate; (void)ld;
    BacnetState *s = (BacnetState *)vstate;
    const uint8_t *buf = StreamSliceGetData(&ss);
    uint32_t len = StreamSliceGetDataLen(&ss);
    if (!buf || len == 0) return APP_LAYER_OK;

    int ret = rs_bacnet_parse(s->rs_state, buf, len);
    if (ret < 0) return APP_LAYER_ERROR;

    /* Sync C-side tx list with Rust tx count */
    uint64_t rust_count = rs_bacnet_get_tx_count(s->rs_state);
    while (s->tx_count < rust_count) {
        if (s->tx_count >= s->tx_alloc) {
            s->tx_alloc *= 2;
            s->txs = realloc(s->txs, s->tx_alloc * sizeof(BacnetTx *));
        }
        BacnetTx *tx = calloc(1, sizeof(BacnetTx));
        if (!tx) return APP_LAYER_ERROR;
        tx->tx_id = s->tx_count;
        tx->rs_tx = rs_bacnet_get_tx(s->rs_state, s->tx_count);
        tx->tx_data.updated_ts = true;
        s->txs[s->tx_count] = tx;
        s->tx_count++;
    }
    return APP_LAYER_OK;
}

static AppLayerResult BacnetParseTC(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    return BacnetParseTS(f, vstate, pstate, ss, ld);
}

static uint64_t BacnetGetTxCnt(void *vstate)
{
    return ((BacnetState *)vstate)->tx_count;
}

static void *BacnetGetTx(void *vstate, uint64_t tx_id)
{
    BacnetState *s = (BacnetState *)vstate;
    if (tx_id < s->tx_count) return s->txs[tx_id];
    return NULL;
}

static int BacnetGetProgress(void *vtx, uint8_t dir)
{
    (void)vtx; (void)dir;
    return 1;
}

static void BacnetTxFree(void *vstate, uint64_t tx_id)
{
    BacnetState *s = (BacnetState *)vstate;
    if (tx_id < s->tx_count && s->txs[tx_id]) {
        rs_bacnet_tx_free(s->rs_state, tx_id);
        free(s->txs[tx_id]);
        s->txs[tx_id] = NULL;
    }
}

static AppLayerTxData *BacnetGetTxData(void *vtx)
{
    return &((BacnetTx *)vtx)->tx_data;
}

static AppLayerStateData *BacnetGetStateData(void *vstate)
{
    return &((BacnetState *)vstate)->state_data;
}

/* Registration */
void BacnetParserRegister(void)
{
    SCLogNotice("Registering BACnet application-layer parser");

    AppLayerParser parser = {
        .name              = "bacnet",
        .default_port      = "[47808]",
        .ip_proto          = IPPROTO_UDP,
        .ProbeTS           = BacnetProbe,
        .ProbeTC           = BacnetProbe,
        .min_depth         = 0,
        .max_depth         = 8,
        .StateAlloc        = BacnetStateAlloc,
        .StateFree         = BacnetStateFree,
        .ParseTS           = BacnetParseTS,
        .ParseTC           = BacnetParseTC,
        .StateGetTxCnt     = BacnetGetTxCnt,
        .StateGetTx        = BacnetGetTx,
        .StateTransactionFree = BacnetTxFree,
        .complete_ts       = 1,
        .complete_tc       = 1,
        .StateGetProgress  = BacnetGetProgress,
        .GetTxData         = BacnetGetTxData,
        .GetStateData      = BacnetGetStateData,
        .flags             = 0,
    };

    ALPROTO_Bacnet = AppLayerRegisterProtocolDetection(&parser, 1);
    if (ALPROTO_Bacnet == ALPROTO_UNKNOWN) {
        SCLogError("Failed to register BACnet protocol detection");
        return;
    }
    AppLayerRegisterParser(&parser, ALPROTO_Bacnet);
    SCLogNotice("bacnet parser registered (ALPROTO=%d)", ALPROTO_Bacnet);
}
