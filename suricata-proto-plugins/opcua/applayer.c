/* Fidelis Farm & Technologies, LLC OPC UA Parser — Suricata App-Layer Registration
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

#include "opcua-plugin.h"

/* Rust FFI */
extern int rs_opcua_probe(const uint8_t *buf, uint32_t len);
extern void *rs_opcua_state_new(void);
extern void rs_opcua_state_free(void *state);
extern int rs_opcua_parse(void *state, const uint8_t *buf, uint32_t len);
extern uint64_t rs_opcua_get_tx_count(const void *state);
extern const void *rs_opcua_get_tx(const void *state, uint64_t tx_index);
extern void rs_opcua_tx_free(void *state, uint64_t tx_id);

/* Logging helpers */
void opcua_log_notice(const char *msg) { SCLogNotice("opcua: %s", msg); }
void opcua_log_error(const char *msg)  { SCLogError("opcua: %s", msg); }

/* C-side wrappers for Suricata bookkeeping */
typedef struct OpcuaTx_ {
    AppLayerTxData tx_data;
    const void *rs_tx;
    uint64_t tx_id;
} OpcuaTx;

typedef struct OpcuaState_ {
    AppLayerStateData state_data;
    void *rs_state;
    OpcuaTx **txs;
    uint64_t tx_count;
    uint64_t tx_alloc;
} OpcuaState;

/* Callbacks */
static AppProto ALPROTO_Opcua = ALPROTO_UNKNOWN;

static AppProto OpcuaProbe(
    const Flow *f, uint8_t direction, const uint8_t *buf, uint32_t len,
    uint8_t *rdir)
{
    (void)f; (void)direction; (void)rdir;
    if (rs_opcua_probe(buf, len)) return ALPROTO_Opcua;
    return ALPROTO_UNKNOWN;
}

static void *OpcuaStateAlloc(void *orig, AppProto p)
{
    (void)orig; (void)p;
    OpcuaState *s = calloc(1, sizeof(OpcuaState));
    if (!s) return NULL;
    s->rs_state = rs_opcua_state_new();
    s->tx_alloc = 16;
    s->txs = calloc(s->tx_alloc, sizeof(OpcuaTx *));
    return s;
}

static void OpcuaStateFree(void *vstate)
{
    OpcuaState *s = (OpcuaState *)vstate;
    if (!s) return;
    for (uint64_t i = 0; i < s->tx_count; i++) {
        if (s->txs[i]) free(s->txs[i]);
    }
    free(s->txs);
    rs_opcua_state_free(s->rs_state);
    free(s);
}

static AppLayerResult OpcuaParseTS(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    (void)f; (void)pstate; (void)ld;
    OpcuaState *s = (OpcuaState *)vstate;
    const uint8_t *buf = StreamSliceGetData(&ss);
    uint32_t len = StreamSliceGetDataLen(&ss);
    if (!buf || len == 0) return APP_LAYER_OK;

    int ret = rs_opcua_parse(s->rs_state, buf, len);
    if (ret < 0) return APP_LAYER_ERROR;

    /* Sync C-side tx list with Rust tx count */
    uint64_t rust_count = rs_opcua_get_tx_count(s->rs_state);
    while (s->tx_count < rust_count) {
        if (s->tx_count >= s->tx_alloc) {
            s->tx_alloc *= 2;
            s->txs = realloc(s->txs, s->tx_alloc * sizeof(OpcuaTx *));
        }
        OpcuaTx *tx = calloc(1, sizeof(OpcuaTx));
        if (!tx) return APP_LAYER_ERROR;
        tx->tx_id = s->tx_count;
        tx->rs_tx = rs_opcua_get_tx(s->rs_state, s->tx_count);
        tx->tx_data.updated_ts = true;
        s->txs[s->tx_count] = tx;
        s->tx_count++;
    }
    return APP_LAYER_OK;
}

static AppLayerResult OpcuaParseTC(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    return OpcuaParseTS(f, vstate, pstate, ss, ld);
}

static uint64_t OpcuaGetTxCnt(void *vstate)
{
    return ((OpcuaState *)vstate)->tx_count;
}

static void *OpcuaGetTx(void *vstate, uint64_t tx_id)
{
    OpcuaState *s = (OpcuaState *)vstate;
    if (tx_id < s->tx_count) return s->txs[tx_id];
    return NULL;
}

static int OpcuaGetProgress(void *vtx, uint8_t dir)
{
    (void)vtx; (void)dir;
    return 1;
}

static void OpcuaTxFree(void *vstate, uint64_t tx_id)
{
    OpcuaState *s = (OpcuaState *)vstate;
    if (tx_id < s->tx_count && s->txs[tx_id]) {
        rs_opcua_tx_free(s->rs_state, tx_id);
        free(s->txs[tx_id]);
        s->txs[tx_id] = NULL;
    }
}

static AppLayerTxData *OpcuaGetTxData(void *vtx)
{
    return &((OpcuaTx *)vtx)->tx_data;
}

static AppLayerStateData *OpcuaGetStateData(void *vstate)
{
    return &((OpcuaState *)vstate)->state_data;
}

/* Registration */
void OpcuaParserRegister(void)
{
    SCLogNotice("Registering OPC UA application-layer parser");

    AppLayerParser parser = {
        .name              = "opcua",
        .default_port      = "[4840]",
        .ip_proto          = IPPROTO_TCP,
        .ProbeTS           = OpcuaProbe,
        .ProbeTC           = OpcuaProbe,
        .min_depth         = 0,
        .max_depth         = 16,
        .StateAlloc        = OpcuaStateAlloc,
        .StateFree         = OpcuaStateFree,
        .ParseTS           = OpcuaParseTS,
        .ParseTC           = OpcuaParseTC,
        .StateGetTxCnt     = OpcuaGetTxCnt,
        .StateGetTx        = OpcuaGetTx,
        .StateTransactionFree = OpcuaTxFree,
        .complete_ts       = 1,
        .complete_tc       = 1,
        .StateGetProgress  = OpcuaGetProgress,
        .GetTxData         = OpcuaGetTxData,
        .GetStateData      = OpcuaGetStateData,
        .flags             = 0,
    };

    ALPROTO_Opcua = AppLayerRegisterProtocolDetection(&parser, 1);
    if (ALPROTO_Opcua == ALPROTO_UNKNOWN) {
        SCLogError("Failed to register OPC UA protocol detection");
        return;
    }
    AppLayerRegisterParser(&parser, ALPROTO_Opcua);
    SCLogNotice("opcua parser registered (ALPROTO=%d)", ALPROTO_Opcua);
}
