/* Fidelis Farm & Technologies, LLC Siemens S7comm Parser Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"

#include "s7comm-plugin.h"

extern void S7commParserRegister(void);

static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish Siemens S7comm parser plugin");

    SCAppLayerPlugin plugin = {
        .name = "s7comm",
        .Register = S7commParserRegister,
        .KeywordsRegister = NULL,
        .logname = "s7comm",
        .confname = "s7comm",
        .dir = 0,
        .Logger = NULL,
    };
    SCPluginRegisterAppLayer(&plugin);
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-s7comm-parser",
    .plugin_version = S7COMM_PLUGIN_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
