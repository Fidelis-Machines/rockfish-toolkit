/* Rockfish Suricata Transport Performance Plugin
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Per-flow TCP / UDP performance metrics:
 *   - TCP handshake RTT, retransmit count, zero-window count, RST count,
 *     out-of-order count, peak/min window size.
 *   - UDP request/response RTT, inter-arrival jitter, packet count.
 *
 * Emits one JSON line per flow termination to a configurable file
 * (default /var/log/suricata/transport_perf.json) so rockfish-perf can
 * ingest deeper signals than the standard EVE flow event provides.
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"
#include "conf.h"

#include "transport-perf.h"

static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish Transport Performance plugin v%s",
                ROCKFISH_TRANSPORT_PERF_VERSION);
    RockfishTransportPerfRegister();
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-transport-perf",
    .plugin_version = ROCKFISH_TRANSPORT_PERF_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
