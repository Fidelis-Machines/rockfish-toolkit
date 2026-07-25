/* Rockfish EtherNet/IP (CIP) Parser Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Plugin entry point — registers the EtherNet/IP application-layer parser
 * and EVE JSON logger with Suricata.
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"

#include "enip-plugin.h"

/* External registration function (defined in applayer.c) */
extern void EnipParserRegister(void);

/**
 * Plugin initialization callback.
 * Called when the plugin shared library is loaded by Suricata.
 */
static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish EtherNet/IP (CIP) parser plugin");
    EnipParserRegister();
}

/**
 * Plugin registration structure.
 * Returned by SCPluginRegister() — the entry point Suricata dlsym()s.
 */
const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-enip-parser",
    .plugin_version = ENIP_PLUGIN_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

/**
 * Plugin entry point.
 * Called by Suricata via dlsym() when the plugin .so is loaded.
 */
const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
