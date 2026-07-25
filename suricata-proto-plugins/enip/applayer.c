/* Rockfish EtherNet/IP (CIP) Parser — Suricata App-Layer Registration
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Registers the EtherNet/IP protocol with Suricata's app-layer framework.
 * Routes callbacks to the Rust parser via FFI.
 */

#include "suricata-common.h"
#include "suricata-plugin.h"
#include "util-debug.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"
#include "output-json.h"

#include "enip-plugin.h"

/* ====================================================================
 * Rust FFI declarations (implemented in src/lib.rs)
 * ==================================================================== */

/* Protocol probing */
extern int rs_enip_probe(const uint8_t *buf, uint32_t len);

/* State lifecycle */
extern void *rs_enip_state_new(void);
extern void rs_enip_state_free(void *state);

/* Parsing */
extern int rs_enip_parse(void *state, const uint8_t *buf, uint32_t len);

/* Transaction access */
extern uint64_t rs_enip_get_tx_count(const void *state);
extern const void *rs_enip_get_tx(const void *state, uint64_t tx_index);
extern void rs_enip_tx_set_logged(void *state, uint64_t tx_index);
extern void rs_enip_state_gc(void *state);

/* EVE JSON logging */
extern char *rs_enip_tx_get_json(const void *tx);
extern void rs_enip_json_free(char *ptr);

/* Detection keywords */
extern char *rs_enip_tx_get_command(const void *tx);
extern char *rs_enip_tx_get_cip_service(const void *tx);
extern uint16_t rs_enip_tx_get_cip_class(const void *tx);
extern uint32_t rs_enip_tx_get_session_handle(const void *tx);

/* ====================================================================
 * Logging helpers (called from Rust)
 * ==================================================================== */

void enip_log_notice(const char *msg)
{
    SCLogNotice("enip: %s", msg);
}

void enip_log_error(const char *msg)
{
    SCLogError("enip: %s", msg);
}

/* ====================================================================
 * App-Layer Callbacks
 * ==================================================================== */

static AppProto ALPROTO_ENIP = ALPROTO_UNKNOWN;

/**
 * Protocol probing callback for TCP.
 */
static AppProto EnipTCPProbe(
    Flow *f,
    uint8_t direction,
    const uint8_t *buf,
    uint32_t len)
{
    (void)f;
    (void)direction;

    if (rs_enip_probe(buf, len)) {
        return ALPROTO_ENIP;
    }
    return ALPROTO_UNKNOWN;
}

/**
 * Protocol probing callback for UDP.
 */
static AppProto EnipUDPProbe(
    Flow *f,
    uint8_t direction,
    const uint8_t *buf,
    uint32_t len)
{
    (void)f;
    (void)direction;

    if (rs_enip_probe(buf, len)) {
        return ALPROTO_ENIP;
    }
    return ALPROTO_UNKNOWN;
}

/**
 * Allocate parser state for a new flow.
 */
static void *EnipStateAlloc(void *orig_state, AppProto proto_orig)
{
    (void)orig_state;
    (void)proto_orig;
    return rs_enip_state_new();
}

/**
 * Free parser state when flow is cleaned up.
 */
static void EnipStateFree(void *state)
{
    rs_enip_state_free(state);
}

/**
 * Parse EtherNet/IP data in the to-server direction.
 */
static AppLayerResult EnipParseRequest(
    Flow *f,
    void *state,
    AppLayerParserState *pstate,
    StreamSlice stream_slice,
    void *local_data)
{
    (void)f;
    (void)pstate;
    (void)local_data;

    const uint8_t *buf = StreamSliceGetData(&stream_slice);
    uint32_t len = StreamSliceGetDataLen(&stream_slice);

    if (buf == NULL || len == 0) {
        return APP_LAYER_OK;
    }

    int ret = rs_enip_parse(state, buf, len);
    if (ret < 0) {
        return APP_LAYER_ERROR;
    }
    return APP_LAYER_OK;
}

/**
 * Parse EtherNet/IP data in the to-client direction.
 */
static AppLayerResult EnipParseResponse(
    Flow *f,
    void *state,
    AppLayerParserState *pstate,
    StreamSlice stream_slice,
    void *local_data)
{
    return EnipParseRequest(f, state, pstate, stream_slice, local_data);
}

/**
 * Get the number of transactions in the state.
 */
static uint64_t EnipGetTxCnt(void *state)
{
    return rs_enip_get_tx_count(state);
}

/**
 * Get a transaction by index.
 */
static void *EnipGetTx(void *state, uint64_t tx_id)
{
    return (void *)rs_enip_get_tx(state, tx_id);
}

/**
 * Get the completion status of a transaction.
 */
static int EnipGetAlstateProgress(void *tx, uint8_t direction)
{
    (void)tx;
    (void)direction;
    return 1;
}

/**
 * Garbage collect completed transactions.
 */
static void EnipStateTxFree(void *state, uint64_t tx_id)
{
    rs_enip_tx_set_logged(state, tx_id);
    rs_enip_state_gc(state);
}

/* ====================================================================
 * EVE JSON Logger
 * ==================================================================== */

/**
 * EVE JSON logging callback.
 */
static bool EnipLogger(ThreadVars *tv, void *thread_data,
                        const Packet *p, Flow *f, void *state,
                        void *tx, uint64_t tx_id)
{
    (void)tv;
    (void)thread_data;
    (void)p;
    (void)f;
    (void)state;
    (void)tx_id;

    char *json = rs_enip_tx_get_json(tx);
    if (json == NULL) {
        return false;
    }

    SCLogDebug("ENIP tx logged: %s", json);

    rs_enip_json_free(json);
    return true;
}

/* ====================================================================
 * Registration
 * ==================================================================== */

/**
 * Register the EtherNet/IP protocol with Suricata's app-layer framework.
 */
void EnipParserRegister(void)
{
    SCLogNotice("Registering EtherNet/IP (CIP) application-layer parser");

    /* Register the protocol name */
    ALPROTO_ENIP = SCAppLayerRegisterProtocolDetection("enip", 0);
    if (ALPROTO_ENIP == ALPROTO_UNKNOWN) {
        SCLogError("Failed to register EtherNet/IP protocol detection");
        return;
    }

    /* Register TCP probing on port 44818 */
    SCAppLayerProtoDetectPMRegisterPatternCS(
        IPPROTO_TCP, ALPROTO_ENIP,
        "\x65\x00", 2, 0, STREAM_TOSERVER);
    SCAppLayerProtoDetectPMRegisterPatternCS(
        IPPROTO_TCP, ALPROTO_ENIP,
        "\x65\x00", 2, 0, STREAM_TOCLIENT);

    /* Register UDP probing on port 2222 */
    SCAppLayerProtoDetectPMRegisterPatternCS(
        IPPROTO_UDP, ALPROTO_ENIP,
        "\x63\x00", 2, 0, STREAM_TOSERVER);
    SCAppLayerProtoDetectPMRegisterPatternCS(
        IPPROTO_UDP, ALPROTO_ENIP,
        "\x63\x00", 2, 0, STREAM_TOCLIENT);

    /* Register TCP parser callbacks */
    AppLayerParserRegisterStateFuncs(
        IPPROTO_TCP, ALPROTO_ENIP,
        EnipStateAlloc, EnipStateFree);
    AppLayerParserRegisterParser(
        IPPROTO_TCP, ALPROTO_ENIP,
        STREAM_TOSERVER, EnipParseRequest);
    AppLayerParserRegisterParser(
        IPPROTO_TCP, ALPROTO_ENIP,
        STREAM_TOCLIENT, EnipParseResponse);
    AppLayerParserRegisterGetTxCnt(
        IPPROTO_TCP, ALPROTO_ENIP, EnipGetTxCnt);
    AppLayerParserRegisterGetTx(
        IPPROTO_TCP, ALPROTO_ENIP, EnipGetTx);
    AppLayerParserRegisterGetStateProgressFunc(
        IPPROTO_TCP, ALPROTO_ENIP, EnipGetAlstateProgress);
    AppLayerParserRegisterTxFreeFunc(
        IPPROTO_TCP, ALPROTO_ENIP, EnipStateTxFree);

    /* Register UDP parser callbacks */
    AppLayerParserRegisterStateFuncs(
        IPPROTO_UDP, ALPROTO_ENIP,
        EnipStateAlloc, EnipStateFree);
    AppLayerParserRegisterParser(
        IPPROTO_UDP, ALPROTO_ENIP,
        STREAM_TOSERVER, EnipParseRequest);
    AppLayerParserRegisterParser(
        IPPROTO_UDP, ALPROTO_ENIP,
        STREAM_TOCLIENT, EnipParseResponse);
    AppLayerParserRegisterGetTxCnt(
        IPPROTO_UDP, ALPROTO_ENIP, EnipGetTxCnt);
    AppLayerParserRegisterGetTx(
        IPPROTO_UDP, ALPROTO_ENIP, EnipGetTx);
    AppLayerParserRegisterGetStateProgressFunc(
        IPPROTO_UDP, ALPROTO_ENIP, EnipGetAlstateProgress);
    AppLayerParserRegisterTxFreeFunc(
        IPPROTO_UDP, ALPROTO_ENIP, EnipStateTxFree);

    /* Mark protocol detection as complete */
    AppLayerParserRegisterProtocolParsers();

    SCLogNotice("EtherNet/IP parser registered (ALPROTO=%d)", ALPROTO_ENIP);
}
