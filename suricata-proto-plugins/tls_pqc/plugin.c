/* Rockfish Suricata TLS PQC Plugin
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Detects post-quantum key-exchange in TLS handshakes per NIST IR 8547.
 *
 * Emits one `pqc` event per TLS-bearing flow via Suricata's eve-log
 * subsystem. Enable under suricata.yaml eve-log.types: [pqc].
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"
#include "conf.h"

#include "tls-pqc.h"

static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish TLS PQC plugin v%s",
                ROCKFISH_TLS_PQC_VERSION);
    RockfishTlsPqcRegister();
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-tls-pqc",
    .plugin_version = ROCKFISH_TLS_PQC_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
