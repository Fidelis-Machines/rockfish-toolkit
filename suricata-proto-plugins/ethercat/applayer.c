/* Fidelis Farm & Technologies, LLC EtherCAT Parser — Suricata App-Layer Registration
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

#include "ethercat-plugin.h"

/* Rust FFI */
extern int rs_ethercat_probe(const uint8_t *buf, uint32_t len);
extern void *rs_ethercat_state_new(void);
extern void rs_ethercat_state_free(void *state);
extern int rs_ethercat_parse(void *state, const uint8_t *buf, uint32_t len);
extern uint64_t rs_ethercat_get_tx_count(const void *state);
extern const void *rs_ethercat_get_tx(const void *state, uint64_t tx_index);
extern void rs_ethercat_tx_free(void *state, uint64_t tx_id);

/* Logging helpers */
void ethercat_log_notice(const char *msg) { SCLogNotice("ethercat: %s", msg); }
void ethercat_log_error(const char *msg)  { SCLogError("ethercat: %s", msg); }

/* C-side wrappers for Suricata bookkeeping */
typedef struct EthercatTx_ {
    AppLayerTxData tx_data;
    const void *rs_tx;
    uint64_t tx_id;
} EthercatTx;

typedef struct EthercatState_ {
    AppLayerStateData state_data;
    void *rs_state;
    EthercatTx **txs;
    uint64_t tx_count;
    uint64_t tx_alloc;
} EthercatState;

/* Callbacks */
static AppProto ALPROTO_Ethercat = ALPROTO_UNKNOWN;

static AppProto EthercatProbe(
    const Flow *f, uint8_t direction, const uint8_t *buf, uint32_t len,
    uint8_t *rdir)
{
    (void)f; (void)direction; (void)rdir;
    if (rs_ethercat_probe(buf, len)) return ALPROTO_Ethercat;
    return ALPROTO_UNKNOWN;
}

static void *EthercatStateAlloc(void *orig, AppProto p)
{
    (void)orig; (void)p;
    EthercatState *s = calloc(1, sizeof(EthercatState));
    if (!s) return NULL;
    s->rs_state = rs_ethercat_state_new();
    s->tx_alloc = 16;
    s->txs = calloc(s->tx_alloc, sizeof(EthercatTx *));
    return s;
}

static void EthercatStateFree(void *vstate)
{
    EthercatState *s = (EthercatState *)vstate;
    if (!s) return;
    for (uint64_t i = 0; i < s->tx_count; i++) {
        if (s->txs[i]) free(s->txs[i]);
    }
    free(s->txs);
    rs_ethercat_state_free(s->rs_state);
    free(s);
}

static AppLayerResult EthercatParseTS(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    (void)f; (void)pstate; (void)ld;
    EthercatState *s = (EthercatState *)vstate;
    const uint8_t *buf = StreamSliceGetData(&ss);
    uint32_t len = StreamSliceGetDataLen(&ss);
    if (!buf || len == 0) return APP_LAYER_OK;

    int ret = rs_ethercat_parse(s->rs_state, buf, len);
    if (ret < 0) return APP_LAYER_ERROR;

    /* Sync C-side tx list with Rust tx count */
    uint64_t rust_count = rs_ethercat_get_tx_count(s->rs_state);
    while (s->tx_count < rust_count) {
        if (s->tx_count >= s->tx_alloc) {
            s->tx_alloc *= 2;
            s->txs = realloc(s->txs, s->tx_alloc * sizeof(EthercatTx *));
        }
        EthercatTx *tx = calloc(1, sizeof(EthercatTx));
        if (!tx) return APP_LAYER_ERROR;
        tx->tx_id = s->tx_count;
        tx->rs_tx = rs_ethercat_get_tx(s->rs_state, s->tx_count);
        tx->tx_data.updated_ts = true;
        s->txs[s->tx_count] = tx;
        s->tx_count++;
    }
    return APP_LAYER_OK;
}

static AppLayerResult EthercatParseTC(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    return EthercatParseTS(f, vstate, pstate, ss, ld);
}

static uint64_t EthercatGetTxCnt(void *vstate)
{
    return ((EthercatState *)vstate)->tx_count;
}

static void *EthercatGetTx(void *vstate, uint64_t tx_id)
{
    EthercatState *s = (EthercatState *)vstate;
    if (tx_id < s->tx_count) return s->txs[tx_id];
    return NULL;
}

static int EthercatGetProgress(void *vtx, uint8_t dir)
{
    (void)vtx; (void)dir;
    return 1;
}

static void EthercatTxFree(void *vstate, uint64_t tx_id)
{
    EthercatState *s = (EthercatState *)vstate;
    if (tx_id < s->tx_count && s->txs[tx_id]) {
        rs_ethercat_tx_free(s->rs_state, tx_id);
        free(s->txs[tx_id]);
        s->txs[tx_id] = NULL;
    }
}

static AppLayerTxData *EthercatGetTxData(void *vtx)
{
    return &((EthercatTx *)vtx)->tx_data;
}

static AppLayerStateData *EthercatGetStateData(void *vstate)
{
    return &((EthercatState *)vstate)->state_data;
}

/* Registration */
void EthercatParserRegister(void)
{
    SCLogNotice("Registering EtherCAT application-layer parser");

    AppLayerParser parser = {
        .name              = "ethercat",
        .default_port      = "[34980]",
        .ip_proto          = IPPROTO_UDP,
        .ProbeTS           = EthercatProbe,
        .ProbeTC           = EthercatProbe,
        .min_depth         = 0,
        .max_depth         = 4,
        .StateAlloc        = EthercatStateAlloc,
        .StateFree         = EthercatStateFree,
        .ParseTS           = EthercatParseTS,
        .ParseTC           = EthercatParseTC,
        .StateGetTxCnt     = EthercatGetTxCnt,
        .StateGetTx        = EthercatGetTx,
        .StateTransactionFree = EthercatTxFree,
        .complete_ts       = 1,
        .complete_tc       = 1,
        .StateGetProgress  = EthercatGetProgress,
        .GetTxData         = EthercatGetTxData,
        .GetStateData      = EthercatGetStateData,
        .flags             = 0,
    };

    ALPROTO_Ethercat = AppLayerRegisterProtocolDetection(&parser, 1);
    if (ALPROTO_Ethercat == ALPROTO_UNKNOWN) {
        SCLogError("Failed to register EtherCAT protocol detection");
        return;
    }
    AppLayerRegisterParser(&parser, ALPROTO_Ethercat);
    SCLogNotice("ethercat parser registered (ALPROTO=%d)", ALPROTO_Ethercat);
}
