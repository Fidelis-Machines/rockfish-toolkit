/* Rockfish Suricata Transport Signals Plugin
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Per-flow TCP / UDP signal metrics:
 *   - TCP handshake RTT, retransmit count, zero-window count, RST count,
 *     out-of-order count, peak/min window size.
 *   - UDP request/response RTT, inter-arrival jitter, packet count.
 *
 * Emits tcp_signals / udp_signals events through Suricata's eve-log
 * pipeline. Downstream consumers (e.g. rockfish-perf) join these by
 * flow_id with the standard flow event to derive per-flow odometry.
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"
#include "conf.h"

#include "transport-signals.h"

static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish Transport Signals plugin v%s",
                ROCKFISH_TRANSPORT_SIGNALS_VERSION);
    RockfishTransportSignalsRegister();
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-transport-signals",
    .plugin_version = ROCKFISH_TRANSPORT_SIGNALS_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
