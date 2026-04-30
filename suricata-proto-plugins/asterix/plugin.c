/* Fidelis Farm & Technologies, LLC ASTERIX Parser Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"

#include "asterix-plugin.h"

extern void AsterixParserRegister(void);

static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish ASTERIX parser plugin");

    SCAppLayerPlugin plugin = {
        .name = "asterix",
        .Register = AsterixParserRegister,
        .KeywordsRegister = NULL,
        .logname = "asterix",
        .confname = "asterix",
        .dir = 0,
        .Logger = NULL,
    };
    SCPluginRegisterAppLayer(&plugin);
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-asterix-parser",
    .plugin_version = ASTERIX_PLUGIN_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
