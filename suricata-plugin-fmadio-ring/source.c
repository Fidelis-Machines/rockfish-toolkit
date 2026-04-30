/* FMADIO Ring Buffer Capture Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "suricata-common.h"
#include "suricata.h"
#include "threadvars.h"
#include "tm-modules.h"
#include "tm-threads-common.h"
#include "tm-threads.h"
#include "packet.h"
#include "decode.h"

#include "source.h"

/* ============================================================================
 * Wrapper functions for Rust FFI
 * These wrap Suricata functions/macros/inline functions to make them
 * callable from Rust. Many Suricata functions are inline or macros that
 * can't be called directly from Rust.
 * ============================================================================ */

/* Logging wrappers */
void fmadio_log_notice(const char *msg)
{
    SCLogNotice("%s", msg);
}

void fmadio_log_error(const char *msg)
{
    SCLogError("%s", msg);
}

/* Packet pool wrappers */
void fmadio_packet_pool_wait(void)
{
    PacketPoolWait();
}

Packet *fmadio_packet_get_from_queue_or_alloc(void)
{
    return PacketGetFromQueueOrAlloc();
}

void fmadio_return_packet_to_pool(ThreadVars *tv, Packet *p)
{
    TmqhOutputPacketpool(tv, p);
}

/* Packet manipulation wrappers */
void fmadio_packet_set_source(Packet *p, uint8_t src)
{
    p->pkt_src = src;
}

void fmadio_packet_set_datalink(Packet *p, int datalink)
{
    p->datalink = datalink;
}

int fmadio_packet_set_data(Packet *p, const uint8_t *data, uint32_t len)
{
    return PacketSetData(p, data, len);
}

void fmadio_packet_set_time(Packet *p, uint64_t secs, uint32_t usecs)
{
    p->ts.secs = secs;
    p->ts.usecs = usecs;
}

/* Thread function wrappers */
void fmadio_threads_set_flag(ThreadVars *tv, uint32_t flag)
{
    TmThreadsSetFlag(tv, flag);
}

/* Get the next slot in the pipeline (for passing to TmThreadsSlotProcessPkt) */
TmSlot *fmadio_get_slot_next(TmSlot *slot)
{
    if (slot == NULL) {
        return NULL;
    }
    return slot->slot_next;
}

int fmadio_slot_process_pkt(ThreadVars *tv, TmSlot *slot, Packet *p)
{
    return TmThreadsSlotProcessPkt(tv, slot, p);
}

void fmadio_capture_handle_timeout(ThreadVars *tv, Packet *p)
{
    TmThreadsCaptureHandleTimeout(tv, p);
}

/* Stats wrappers */
uint16_t fmadio_stats_register_counter(const char *name, ThreadVars *tv)
{
    return StatsRegisterCounter(name, tv);
}

void fmadio_stats_set_ui64(ThreadVars *tv, uint16_t counter, uint64_t value)
{
    StatsSetUI64(tv, counter, value);
}

void fmadio_stats_sync_if_signalled(ThreadVars *tv)
{
    StatsSyncCountersIfSignalled(tv);
}

/* Control flag wrapper */
int fmadio_should_stop(void)
{
    return (suricata_ctl_flags & SURICATA_STOP) ? 1 : 0;
}

/* ============================================================================
 * External Rust FFI functions
 * ============================================================================ */
extern TmEcode fmadio_thread_init(void *tv, const void *initdata, void **data);
extern TmEcode fmadio_pkt_acq_loop(void *tv, void *data, void *slot);
extern TmEcode fmadio_pkt_acq_break_loop(void *tv, void *data);
extern TmEcode fmadio_thread_deinit(void *tv, void *data);
extern void fmadio_thread_exit_print_stats(void *tv, void *data);

/**
 * Decode thread initialization.
 * Allocates DecodeThreadVars and registers performance counters.
 */
static TmEcode DecodeFmadioRingThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogDebug("DecodeFmadioRingThreadInit");

    DecodeThreadVars *dtv = DecodeThreadVarsAlloc(tv);
    if (dtv == NULL) {
        SCReturnInt(TM_ECODE_FAILED);
    }
    DecodeRegisterPerfCounters(dtv, tv);
    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * Decode thread deinitialization.
 */
static TmEcode DecodeFmadioRingThreadDeinit(ThreadVars *tv, void *data)
{
    SCLogDebug("DecodeFmadioRingThreadDeinit");

    if (data != NULL) {
        DecodeThreadVarsFree(tv, data);
    }
    SCReturnInt(TM_ECODE_OK);
}

/**
 * Decode a packet from FMADIO Ring.
 * Called by the thread pipeline for each packet after it's received.
 */
static TmEcode DecodeFmadioRing(ThreadVars *tv, Packet *p, void *data)
{
    SCLogDebug("DecodeFmadioRing: packet len=%u", GET_PKT_LEN(p));

    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* Update packet counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* Decode link layer based on datalink type */
    DecodeLinkLayer(tv, dtv, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    /* Finalize packet processing */
    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * Register the FMADIO Ring receive thread module.
 */
void TmModuleReceiveFmadioRingRegister(int slot)
{
    SCLogDebug("Registering ReceiveFmadioRing in slot %d", slot);

    tmm_modules[slot].name = "ReceiveFmadioRing";
    tmm_modules[slot].ThreadInit = (TmEcode (*)(ThreadVars *, const void *, void **))fmadio_thread_init;
    tmm_modules[slot].Func = NULL;  /* Not used for receive modules */
    tmm_modules[slot].PktAcqLoop = (TmEcode (*)(ThreadVars *, void *, void *))fmadio_pkt_acq_loop;
    tmm_modules[slot].PktAcqBreakLoop = (TmEcode (*)(ThreadVars *, void *))fmadio_pkt_acq_break_loop;
    tmm_modules[slot].ThreadExitPrintStats = (void (*)(ThreadVars *, void *))fmadio_thread_exit_print_stats;
    tmm_modules[slot].ThreadDeinit = (TmEcode (*)(ThreadVars *, void *))fmadio_thread_deinit;
    tmm_modules[slot].cap_flags = 0;
    tmm_modules[slot].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * Register the FMADIO Ring decode thread module.
 */
void TmModuleDecodeFmadioRingRegister(int slot)
{
    SCLogDebug("Registering DecodeFmadioRing in slot %d", slot);

    tmm_modules[slot].name = "DecodeFmadioRing";
    tmm_modules[slot].ThreadInit = DecodeFmadioRingThreadInit;
    tmm_modules[slot].Func = DecodeFmadioRing;
    tmm_modules[slot].ThreadExitPrintStats = NULL;
    tmm_modules[slot].ThreadDeinit = DecodeFmadioRingThreadDeinit;
    tmm_modules[slot].cap_flags = 0;
    tmm_modules[slot].flags = TM_FLAG_DECODE_TM;
}
