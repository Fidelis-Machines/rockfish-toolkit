/* FMADIO Ring Buffer Capture Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "suricata-common.h"
#include "suricata.h"
#include "runmodes.h"
#include "tm-threads.h"
#include "util-affinity.h"
#include "util-device.h"

#include "runmode.h"
#include "source.h"

/* Thread name prefixes */
static const char *fmadio_thread_name_single = "RxFmadioRing";
static const char *fmadio_thread_name_workers = "W#FmadioRing";

/* External functions to get ring configuration from plugin.c */
extern int FmadioRingGetCount(void);
extern const char *FmadioRingGetPathByIndex(int index);

/**
 * Get the default runmode for FMADIO Ring capture.
 */
const char *FmadioRingGetDefaultRunMode(void)
{
    return "workers";
}

/**
 * Create a worker thread for a specific ring buffer.
 *
 * @param ring_path Path to the ring buffer
 * @param ring_id Ring identifier (0-based index)
 * @param thread_prefix Thread name prefix
 * @return 0 on success, -1 on failure
 */
static int CreateRingThread(const char *ring_path, int ring_id,
                            const char *thread_prefix)
{
    if (ring_path == NULL) {
        SCLogError("Ring path is NULL for ring %d", ring_id);
        return -1;
    }

    char thread_name[TM_THREAD_NAME_MAX];
    snprintf(thread_name, sizeof(thread_name), "%s%d", thread_prefix, ring_id);

    SCLogNotice("Creating thread '%s' for ring: %s", thread_name, ring_path);

    ThreadVars *tv = TmThreadCreatePacketHandler(thread_name,
            "packetpool", "packetpool",
            "packetpool", "packetpool",
            "pktacqloop");
    if (tv == NULL) {
        SCLogError("TmThreadCreatePacketHandler failed for ring %d", ring_id);
        return -1;
    }

    TmModule *tm_module = TmModuleGetByName("ReceiveFmadioRing");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName failed for ReceiveFmadioRing");
    }
    /* Pass ring_path as initdata to the thread module */
    TmSlotSetFuncAppend(tv, tm_module, (void *)ring_path);

    tm_module = TmModuleGetByName("DecodeFmadioRing");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName failed for DecodeFmadioRing");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName failed for FlowWorker");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    TmThreadSetCPU(tv, WORKER_CPU_SET);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        FatalError("TmThreadSpawn failed for ring %d", ring_id);
    }

    return 0;
}

/**
 * Single-threaded runmode.
 * Creates one thread per configured ring buffer.
 */
static int RunModeSingle(void)
{
    int ring_count = FmadioRingGetCount();
    if (ring_count == 0) {
        SCLogError("No FMADIO rings configured");
        return -1;
    }

    SCLogNotice("Running FMADIO Ring in single mode with %d ring(s)", ring_count);

    for (int i = 0; i < ring_count; i++) {
        const char *ring_path = FmadioRingGetPathByIndex(i);
        if (CreateRingThread(ring_path, i, fmadio_thread_name_single) != 0) {
            return -1;
        }
    }

    return 0;
}

/**
 * Workers runmode.
 * Each worker thread handles all processing for its ring's packets.
 * This is the recommended mode for FMADIO Ring.
 */
static int RunModeWorkers(void)
{
    int ring_count = FmadioRingGetCount();
    if (ring_count == 0) {
        SCLogError("No FMADIO rings configured");
        return -1;
    }

    SCLogNotice("Running FMADIO Ring in workers mode with %d ring(s)", ring_count);

    for (int i = 0; i < ring_count; i++) {
        const char *ring_path = FmadioRingGetPathByIndex(i);
        if (CreateRingThread(ring_path, i, fmadio_thread_name_workers) != 0) {
            return -1;
        }
    }

    return 0;
}

/**
 * Register FMADIO Ring runmodes with Suricata.
 */
void FmadioRingRunmodeRegister(int slot)
{
    SCLogDebug("Registering FMADIO Ring runmodes in slot %d", slot);

    RunModeRegisterNewRunMode(slot, "single",
            "Single threaded FMADIO Ring mode",
            RunModeSingle, NULL);

    RunModeRegisterNewRunMode(slot, "workers",
            "Workers mode - each thread handles all processing (recommended)",
            RunModeWorkers, NULL);
}
