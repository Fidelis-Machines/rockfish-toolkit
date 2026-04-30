/* Fidelis Farm & Technologies, LLC IEC 60870-5-104 Parser — Suricata App-Layer Registration
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

#include "iec104-plugin.h"

/* Rust FFI */
extern int rs_iec104_probe(const uint8_t *buf, uint32_t len);
extern void *rs_iec104_state_new(void);
extern void rs_iec104_state_free(void *state);
extern int rs_iec104_parse(void *state, const uint8_t *buf, uint32_t len);
extern uint64_t rs_iec104_get_tx_count(const void *state);
extern const void *rs_iec104_get_tx(const void *state, uint64_t tx_index);
extern void rs_iec104_tx_free(void *state, uint64_t tx_id);

/* Logging helpers */
void iec104_log_notice(const char *msg) { SCLogNotice("iec104: %s", msg); }
void iec104_log_error(const char *msg)  { SCLogError("iec104: %s", msg); }

/* C-side wrappers for Suricata bookkeeping */
typedef struct Iec104Tx_ {
    AppLayerTxData tx_data;
    const void *rs_tx;
    uint64_t tx_id;
} Iec104Tx;

typedef struct Iec104State_ {
    AppLayerStateData state_data;
    void *rs_state;
    Iec104Tx **txs;
    uint64_t tx_count;
    uint64_t tx_alloc;
} Iec104State;

/* Callbacks */
static AppProto ALPROTO_Iec104 = ALPROTO_UNKNOWN;

static AppProto Iec104Probe(
    const Flow *f, uint8_t direction, const uint8_t *buf, uint32_t len,
    uint8_t *rdir)
{
    (void)f; (void)direction; (void)rdir;
    if (rs_iec104_probe(buf, len)) return ALPROTO_Iec104;
    return ALPROTO_UNKNOWN;
}

static void *Iec104StateAlloc(void *orig, AppProto p)
{
    (void)orig; (void)p;
    Iec104State *s = calloc(1, sizeof(Iec104State));
    if (!s) return NULL;
    s->rs_state = rs_iec104_state_new();
    s->tx_alloc = 16;
    s->txs = calloc(s->tx_alloc, sizeof(Iec104Tx *));
    return s;
}

static void Iec104StateFree(void *vstate)
{
    Iec104State *s = (Iec104State *)vstate;
    if (!s) return;
    for (uint64_t i = 0; i < s->tx_count; i++) {
        if (s->txs[i]) free(s->txs[i]);
    }
    free(s->txs);
    rs_iec104_state_free(s->rs_state);
    free(s);
}

static AppLayerResult Iec104ParseTS(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    (void)f; (void)pstate; (void)ld;
    Iec104State *s = (Iec104State *)vstate;
    const uint8_t *buf = StreamSliceGetData(&ss);
    uint32_t len = StreamSliceGetDataLen(&ss);
    if (!buf || len == 0) return APP_LAYER_OK;

    int ret = rs_iec104_parse(s->rs_state, buf, len);
    if (ret < 0) return APP_LAYER_ERROR;

    /* Sync C-side tx list with Rust tx count */
    uint64_t rust_count = rs_iec104_get_tx_count(s->rs_state);
    while (s->tx_count < rust_count) {
        if (s->tx_count >= s->tx_alloc) {
            s->tx_alloc *= 2;
            s->txs = realloc(s->txs, s->tx_alloc * sizeof(Iec104Tx *));
        }
        Iec104Tx *tx = calloc(1, sizeof(Iec104Tx));
        if (!tx) return APP_LAYER_ERROR;
        tx->tx_id = s->tx_count;
        tx->rs_tx = rs_iec104_get_tx(s->rs_state, s->tx_count);
        tx->tx_data.updated_ts = true;
        s->txs[s->tx_count] = tx;
        s->tx_count++;
    }
    return APP_LAYER_OK;
}

static AppLayerResult Iec104ParseTC(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    return Iec104ParseTS(f, vstate, pstate, ss, ld);
}

static uint64_t Iec104GetTxCnt(void *vstate)
{
    return ((Iec104State *)vstate)->tx_count;
}

static void *Iec104GetTx(void *vstate, uint64_t tx_id)
{
    Iec104State *s = (Iec104State *)vstate;
    if (tx_id < s->tx_count) return s->txs[tx_id];
    return NULL;
}

static int Iec104GetProgress(void *vtx, uint8_t dir)
{
    (void)vtx; (void)dir;
    return 1;
}

static void Iec104TxFree(void *vstate, uint64_t tx_id)
{
    Iec104State *s = (Iec104State *)vstate;
    if (tx_id < s->tx_count && s->txs[tx_id]) {
        rs_iec104_tx_free(s->rs_state, tx_id);
        free(s->txs[tx_id]);
        s->txs[tx_id] = NULL;
    }
}

static AppLayerTxData *Iec104GetTxData(void *vtx)
{
    return &((Iec104Tx *)vtx)->tx_data;
}

static AppLayerStateData *Iec104GetStateData(void *vstate)
{
    return &((Iec104State *)vstate)->state_data;
}

/* Registration */
void Iec104ParserRegister(void)
{
    SCLogNotice("Registering IEC 60870-5-104 application-layer parser");

    AppLayerParser parser = {
        .name              = "iec104",
        .default_port      = "[2404]",
        .ip_proto          = IPPROTO_TCP,
        .ProbeTS           = Iec104Probe,
        .ProbeTC           = Iec104Probe,
        .min_depth         = 0,
        .max_depth         = 6,
        .StateAlloc        = Iec104StateAlloc,
        .StateFree         = Iec104StateFree,
        .ParseTS           = Iec104ParseTS,
        .ParseTC           = Iec104ParseTC,
        .StateGetTxCnt     = Iec104GetTxCnt,
        .StateGetTx        = Iec104GetTx,
        .StateTransactionFree = Iec104TxFree,
        .complete_ts       = 1,
        .complete_tc       = 1,
        .StateGetProgress  = Iec104GetProgress,
        .GetTxData         = Iec104GetTxData,
        .GetStateData      = Iec104GetStateData,
        .flags             = 0,
    };

    ALPROTO_Iec104 = AppLayerRegisterProtocolDetection(&parser, 1);
    if (ALPROTO_Iec104 == ALPROTO_UNKNOWN) {
        SCLogError("Failed to register IEC 60870-5-104 protocol detection");
        return;
    }
    AppLayerRegisterParser(&parser, ALPROTO_Iec104);
    SCLogNotice("iec104 parser registered (ALPROTO=%d)", ALPROTO_Iec104);
}
