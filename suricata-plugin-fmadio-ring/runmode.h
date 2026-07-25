/* FMADIO Ring Buffer Capture Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SURICATA_RUNMODE_FMADIO_RING_H
#define SURICATA_RUNMODE_FMADIO_RING_H

/**
 * Get the default runmode for FMADIO Ring capture.
 *
 * @return "workers" - the recommended mode for FMADIO Ring
 */
const char *FmadioRingGetDefaultRunMode(void);

/**
 * Register FMADIO Ring runmodes with Suricata.
 *
 * @param slot The runmode slot to register in (RUNMODE_PLUGIN)
 */
void FmadioRingRunmodeRegister(int slot);

/**
 * Get the number of configured ring buffers.
 * @return Number of rings (0 if none configured)
 */
int FmadioRingGetCount(void);

/**
 * Get a ring buffer path by index.
 * @param index Ring index (0-based)
 * @return Ring path, or NULL if index out of range
 */
const char *FmadioRingGetPathByIndex(int index);

#endif /* SURICATA_RUNMODE_FMADIO_RING_H */
