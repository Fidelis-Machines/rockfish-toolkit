/* Fidelis Farm & Technologies, LLC ASTERIX Parser — Suricata App-Layer Registration
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

#include "asterix-plugin.h"

/* Rust FFI */
extern int rs_asterix_probe(const uint8_t *buf, uint32_t len);
extern void *rs_asterix_state_new(void);
extern void rs_asterix_state_free(void *state);
extern int rs_asterix_parse(void *state, const uint8_t *buf, uint32_t len);
extern uint64_t rs_asterix_get_tx_count(const void *state);
extern const void *rs_asterix_get_tx(const void *state, uint64_t tx_index);
extern void rs_asterix_tx_free(void *state, uint64_t tx_id);

/* Logging helpers */
void asterix_log_notice(const char *msg) { SCLogNotice("asterix: %s", msg); }
void asterix_log_error(const char *msg)  { SCLogError("asterix: %s", msg); }

/* C-side wrappers for Suricata bookkeeping */
typedef struct AsterixTx_ {
    AppLayerTxData tx_data;
    const void *rs_tx;
    uint64_t tx_id;
} AsterixTx;

typedef struct AsterixState_ {
    AppLayerStateData state_data;
    void *rs_state;
    AsterixTx **txs;
    uint64_t tx_count;
    uint64_t tx_alloc;
} AsterixState;

/* Callbacks */
static AppProto ALPROTO_Asterix = ALPROTO_UNKNOWN;

static AppProto AsterixProbe(
    const Flow *f, uint8_t direction, const uint8_t *buf, uint32_t len,
    uint8_t *rdir)
{
    (void)f; (void)direction; (void)rdir;
    if (rs_asterix_probe(buf, len)) return ALPROTO_Asterix;
    return ALPROTO_UNKNOWN;
}

static void *AsterixStateAlloc(void *orig, AppProto p)
{
    (void)orig; (void)p;
    AsterixState *s = calloc(1, sizeof(AsterixState));
    if (!s) return NULL;
    s->rs_state = rs_asterix_state_new();
    s->tx_alloc = 16;
    s->txs = calloc(s->tx_alloc, sizeof(AsterixTx *));
    return s;
}

static void AsterixStateFree(void *vstate)
{
    AsterixState *s = (AsterixState *)vstate;
    if (!s) return;
    for (uint64_t i = 0; i < s->tx_count; i++) {
        if (s->txs[i]) free(s->txs[i]);
    }
    free(s->txs);
    rs_asterix_state_free(s->rs_state);
    free(s);
}

static AppLayerResult AsterixParseTS(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    (void)f; (void)pstate; (void)ld;
    AsterixState *s = (AsterixState *)vstate;
    const uint8_t *buf = StreamSliceGetData(&ss);
    uint32_t len = StreamSliceGetDataLen(&ss);
    if (!buf || len == 0) return APP_LAYER_OK;

    int ret = rs_asterix_parse(s->rs_state, buf, len);
    if (ret < 0) return APP_LAYER_ERROR;

    /* Sync C-side tx list with Rust tx count */
    uint64_t rust_count = rs_asterix_get_tx_count(s->rs_state);
    while (s->tx_count < rust_count) {
        if (s->tx_count >= s->tx_alloc) {
            s->tx_alloc *= 2;
            s->txs = realloc(s->txs, s->tx_alloc * sizeof(AsterixTx *));
        }
        AsterixTx *tx = calloc(1, sizeof(AsterixTx));
        if (!tx) return APP_LAYER_ERROR;
        tx->tx_id = s->tx_count;
        tx->rs_tx = rs_asterix_get_tx(s->rs_state, s->tx_count);
        tx->tx_data.updated_ts = true;
        s->txs[s->tx_count] = tx;
        s->tx_count++;
    }
    return APP_LAYER_OK;
}

static AppLayerResult AsterixParseTC(
    Flow *f, void *vstate, AppLayerParserState *pstate,
    StreamSlice ss, void *ld)
{
    return AsterixParseTS(f, vstate, pstate, ss, ld);
}

static uint64_t AsterixGetTxCnt(void *vstate)
{
    return ((AsterixState *)vstate)->tx_count;
}

static void *AsterixGetTx(void *vstate, uint64_t tx_id)
{
    AsterixState *s = (AsterixState *)vstate;
    if (tx_id < s->tx_count) return s->txs[tx_id];
    return NULL;
}

static int AsterixGetProgress(void *vtx, uint8_t dir)
{
    (void)vtx; (void)dir;
    return 1;
}

static void AsterixTxFree(void *vstate, uint64_t tx_id)
{
    AsterixState *s = (AsterixState *)vstate;
    if (tx_id < s->tx_count && s->txs[tx_id]) {
        rs_asterix_tx_free(s->rs_state, tx_id);
        free(s->txs[tx_id]);
        s->txs[tx_id] = NULL;
    }
}

static AppLayerTxData *AsterixGetTxData(void *vtx)
{
    return &((AsterixTx *)vtx)->tx_data;
}

static AppLayerStateData *AsterixGetStateData(void *vstate)
{
    return &((AsterixState *)vstate)->state_data;
}

/* Registration */
void AsterixParserRegister(void)
{
    SCLogNotice("Registering ASTERIX application-layer parser");

    AppLayerParser parser = {
        .name              = "asterix",
        .default_port      = "[8600]",
        .ip_proto          = IPPROTO_UDP,
        .ProbeTS           = AsterixProbe,
        .ProbeTC           = AsterixProbe,
        .min_depth         = 0,
        .max_depth         = 4,
        .StateAlloc        = AsterixStateAlloc,
        .StateFree         = AsterixStateFree,
        .ParseTS           = AsterixParseTS,
        .ParseTC           = AsterixParseTC,
        .StateGetTxCnt     = AsterixGetTxCnt,
        .StateGetTx        = AsterixGetTx,
        .StateTransactionFree = AsterixTxFree,
        .complete_ts       = 1,
        .complete_tc       = 1,
        .StateGetProgress  = AsterixGetProgress,
        .GetTxData         = AsterixGetTxData,
        .GetStateData      = AsterixGetStateData,
        .flags             = 0,
    };

    ALPROTO_Asterix = AppLayerRegisterProtocolDetection(&parser, 1);
    if (ALPROTO_Asterix == ALPROTO_UNKNOWN) {
        SCLogError("Failed to register ASTERIX protocol detection");
        return;
    }
    AppLayerRegisterParser(&parser, ALPROTO_Asterix);
    SCLogNotice("asterix parser registered (ALPROTO=%d)", ALPROTO_Asterix);
}
