/* Fidelis Farm & Technologies, LLC IEC 60870-5-104 Parser Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"

#include "iec104-plugin.h"

extern void Iec104ParserRegister(void);

static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish IEC 60870-5-104 parser plugin");

    SCAppLayerPlugin plugin = {
        .name = "iec104",
        .Register = Iec104ParserRegister,
        .KeywordsRegister = NULL,
        .logname = "iec104",
        .confname = "iec104",
        .dir = 0,
        .Logger = NULL,
    };
    SCPluginRegisterAppLayer(&plugin);
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-iec104-parser",
    .plugin_version = IEC104_PLUGIN_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
