/* Fidelis Farm & Technologies, LLC — Shared Suricata Plugin TxData/StateData Wrappers
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Suricata 8 requires every app-layer transaction to embed AppLayerTxData
 * and every state to embed AppLayerStateData. Since our parsers are
 * implemented in Rust without linking to libsuricata, we wrap the Rust
 * opaque state/tx pointers in C-side structs that carry the Suricata
 * bookkeeping fields.
 *
 * Usage in each plugin's applayer.c:
 *   #include "txdata.h"
 *   // Then use PluginState/PluginTx wrappers instead of raw Rust pointers
 */

#ifndef ROCKFISH_PLUGIN_TXDATA_H
#define ROCKFISH_PLUGIN_TXDATA_H

#include "suricata-common.h"
#include "app-layer-parser.h"

/*
 * Wrapper around the Rust transaction pointer.
 * Embeds AppLayerTxData so Suricata can track logging, detection, etc.
 */
typedef struct PluginTx_ {
    AppLayerTxData tx_data;
    void *rs_tx;        /* Opaque pointer to Rust transaction */
    uint64_t tx_id;
} PluginTx;

/*
 * Wrapper around the Rust state pointer.
 * Embeds AppLayerStateData for Suricata's internal state management.
 */
typedef struct PluginState_ {
    AppLayerStateData state_data;
    void *rs_state;     /* Opaque pointer to Rust state */
    /* C-side transaction list wrapping Rust tx pointers */
    PluginTx **txs;
    uint64_t tx_count;
    uint64_t tx_alloc;
} PluginState;

/* Allocate a new PluginState wrapping a Rust state */
static inline PluginState *PluginStateAlloc(void *rs_state_new(void))
{
    PluginState *s = SCCalloc(1, sizeof(PluginState));
    if (s == NULL) return NULL;
    s->rs_state = rs_state_new();
    s->tx_alloc = 16;
    s->txs = SCCalloc(s->tx_alloc, sizeof(PluginTx *));
    return s;
}

/* Add a new transaction wrapping the current Rust tx */
static inline PluginTx *PluginStateAddTx(PluginState *s)
{
    if (s->tx_count >= s->tx_alloc) {
        s->tx_alloc *= 2;
        s->txs = SCrealloc(s->txs, s->tx_alloc * sizeof(PluginTx *));
    }
    PluginTx *tx = SCCalloc(1, sizeof(PluginTx));
    if (tx == NULL) return NULL;
    tx->tx_id = s->tx_count;
    s->txs[s->tx_count] = tx;
    s->tx_count++;
    return tx;
}

/* Get AppLayerTxData from a PluginTx */
static inline AppLayerTxData *PluginGetTxData(void *vtx)
{
    PluginTx *tx = (PluginTx *)vtx;
    return &tx->tx_data;
}

/* Get AppLayerStateData from a PluginState */
static inline AppLayerStateData *PluginGetStateData(void *vstate)
{
    PluginState *state = (PluginState *)vstate;
    return &state->state_data;
}

#endif /* ROCKFISH_PLUGIN_TXDATA_H */
