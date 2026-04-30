/* Fidelis Farm & Technologies, LLC IEC 61850 MMS Parser Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"

#include "iec61850-plugin.h"

extern void Iec61850ParserRegister(void);

static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish IEC 61850 MMS parser plugin");

    SCAppLayerPlugin plugin = {
        .name = "iec61850",
        .Register = Iec61850ParserRegister,
        .KeywordsRegister = NULL,
        .logname = "iec61850",
        .confname = "iec61850",
        .dir = 0,
        .Logger = NULL,
    };
    SCPluginRegisterAppLayer(&plugin);
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-iec61850-parser",
    .plugin_version = IEC61850_PLUGIN_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
