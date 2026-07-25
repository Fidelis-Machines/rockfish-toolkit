/* Fidelis Farm & Technologies, LLC IEC 61850 MMS Parser — Suricata App-Layer Registration
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

#include "iec61850-plugin.h"

/* Rust FFI */
extern int rs_iec61850_probe(const uint8_t *buf, uint32_t len);
extern void *rs_iec61850_state_new(void);
extern void rs_iec61850_state_free(void *state);
extern int rs_iec61850_parse(void *state, const uint8_t *buf, uint32_t len);
extern uint64_t rs_iec61850_get_tx_count(const void *state);
extern const void *rs_iec61850_get_tx(const void *state, uint64_t tx_index);
extern void rs_iec61850_tx_free(void *state, uint64_t tx_id);

/* Logging helpers */
void iec61850_log_notice(const char *msg) { SCLogNotice("iec61850: %s", msg); }
void iec61850_log_error(const char *msg)  { SCLogError("iec61850: %s", msg); }

/* C-side wrappers for Suricata bookkeeping */
typedef struct Iec61850Tx_ {
    AppLayerTxData tx_data;
    const void *rs_tx;
    uint64_t tx_id;
} Iec61850Tx;

typedef struct Iec61850State_ {
    AppLayerStateData state_data;
    void *rs_state;
    Iec61850Tx **txs;
    uint64_t tx_count;
    uint64_t tx_alloc;
} Iec61850State;

/* Callbacks */
static AppProto ALPROTO_Iec61850 = ALPROTO_UNKNOWN;

static AppProto Iec61850Probe(
    const Flow *f, uint8_t direction, const uint8_t *buf, uint32_t len,
    uint8_t *rdir)
{
    (void)f; (void)direction; (void)rdir;
    if (rs_iec61850_probe(buf, len)) return ALPROTO_Iec61850;
    return ALPROTO_UNKNOWN;
}

static void *Iec61850StateAlloc(void *orig, AppProto p)
{
    (void)orig; (void)p;
    Iec61850State *s = calloc(1, sizeof(Iec61850State));
    if (!s) return NULL;
    s->rs_state = rs_iec61850_state_new();
    s->tx_alloc = 16;
    s->txs = calloc(s->tx_alloc, sizeof(Iec61850Tx *));
    return s;
}

static void Iec61850StateFree(void *vstate)
{
    Iec61850State *s = (Iec61850State *)vstate;
    if (!s) return;
    for (uint64_t i = 0; i < s->tx_count; i++) {
        if (s->txs[i]) free(s->txs[i]);
    }
    free(s->txs);
    rs_iec61850_state_free(s->rs_state);
    free(s);
}

static AppLayerResult Iec61850ParseTS(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    (void)f; (void)pstate; (void)ld;
    Iec61850State *s = (Iec61850State *)vstate;
    const uint8_t *buf = StreamSliceGetData(&ss);
    uint32_t len = StreamSliceGetDataLen(&ss);
    if (!buf || len == 0) return APP_LAYER_OK;

    int ret = rs_iec61850_parse(s->rs_state, buf, len);
    if (ret < 0) return APP_LAYER_ERROR;

    /* Sync C-side tx list with Rust tx count */
    uint64_t rust_count = rs_iec61850_get_tx_count(s->rs_state);
    while (s->tx_count < rust_count) {
        if (s->tx_count >= s->tx_alloc) {
            s->tx_alloc *= 2;
            s->txs = realloc(s->txs, s->tx_alloc * sizeof(Iec61850Tx *));
        }
        Iec61850Tx *tx = calloc(1, sizeof(Iec61850Tx));
        if (!tx) return APP_LAYER_ERROR;
        tx->tx_id = s->tx_count;
        tx->rs_tx = rs_iec61850_get_tx(s->rs_state, s->tx_count);
        tx->tx_data.updated_ts = true;
        s->txs[s->tx_count] = tx;
        s->tx_count++;
    }
    return APP_LAYER_OK;
}

static AppLayerResult Iec61850ParseTC(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    return Iec61850ParseTS(f, vstate, pstate, ss, ld);
}

static uint64_t Iec61850GetTxCnt(void *vstate)
{
    return ((Iec61850State *)vstate)->tx_count;
}

static void *Iec61850GetTx(void *vstate, uint64_t tx_id)
{
    Iec61850State *s = (Iec61850State *)vstate;
    if (tx_id < s->tx_count) return s->txs[tx_id];
    return NULL;
}

static int Iec61850GetProgress(void *vtx, uint8_t dir)
{
    (void)vtx; (void)dir;
    return 1;
}

static void Iec61850TxFree(void *vstate, uint64_t tx_id)
{
    Iec61850State *s = (Iec61850State *)vstate;
    if (tx_id < s->tx_count && s->txs[tx_id]) {
        rs_iec61850_tx_free(s->rs_state, tx_id);
        free(s->txs[tx_id]);
        s->txs[tx_id] = NULL;
    }
}

static AppLayerTxData *Iec61850GetTxData(void *vtx)
{
    return &((Iec61850Tx *)vtx)->tx_data;
}

static AppLayerStateData *Iec61850GetStateData(void *vstate)
{
    return &((Iec61850State *)vstate)->state_data;
}

/* Registration */
void Iec61850ParserRegister(void)
{
    SCLogNotice("Registering IEC 61850 MMS application-layer parser");

    AppLayerParser parser = {
        .name              = "iec61850",
        .default_port      = "[102]",
        .ip_proto          = IPPROTO_TCP,
        .ProbeTS           = Iec61850Probe,
        .ProbeTC           = Iec61850Probe,
        .min_depth         = 0,
        .max_depth         = 8,
        .StateAlloc        = Iec61850StateAlloc,
        .StateFree         = Iec61850StateFree,
        .ParseTS           = Iec61850ParseTS,
        .ParseTC           = Iec61850ParseTC,
        .StateGetTxCnt     = Iec61850GetTxCnt,
        .StateGetTx        = Iec61850GetTx,
        .StateTransactionFree = Iec61850TxFree,
        .complete_ts       = 1,
        .complete_tc       = 1,
        .StateGetProgress  = Iec61850GetProgress,
        .GetTxData         = Iec61850GetTxData,
        .GetStateData      = Iec61850GetStateData,
        .flags             = 0,
    };

    ALPROTO_Iec61850 = AppLayerRegisterProtocolDetection(&parser, 1);
    if (ALPROTO_Iec61850 == ALPROTO_UNKNOWN) {
        SCLogError("Failed to register IEC 61850 MMS protocol detection");
        return;
    }
    AppLayerRegisterParser(&parser, ALPROTO_Iec61850);
    SCLogNotice("iec61850 parser registered (ALPROTO=%d)", ALPROTO_Iec61850);
}
