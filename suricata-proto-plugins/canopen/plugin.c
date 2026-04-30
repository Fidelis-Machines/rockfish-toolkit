/* Fidelis Farm & Technologies, LLC CANopen Parser Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"

#include "canopen-plugin.h"

extern void CanopenParserRegister(void);

static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish CANopen parser plugin");

    SCAppLayerPlugin plugin = {
        .name = "canopen",
        .Register = CanopenParserRegister,
        .KeywordsRegister = NULL,
        .logname = "canopen",
        .confname = "canopen",
        .dir = 0,
        .Logger = NULL,
    };
    SCPluginRegisterAppLayer(&plugin);
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-canopen-parser",
    .plugin_version = CANOPEN_PLUGIN_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
