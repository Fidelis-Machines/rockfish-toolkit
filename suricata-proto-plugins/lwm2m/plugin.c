/* Fidelis Farm & Technologies, LLC LwM2M Parser Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"

#include "lwm2m-plugin.h"

extern void Lwm2mParserRegister(void);

static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish LwM2M parser plugin");

    SCAppLayerPlugin plugin = {
        .name = "lwm2m",
        .Register = Lwm2mParserRegister,
        .KeywordsRegister = NULL,
        .logname = "lwm2m",
        .confname = "lwm2m",
        .dir = 0,
        .Logger = NULL,
    };
    SCPluginRegisterAppLayer(&plugin);
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-lwm2m-parser",
    .plugin_version = LWM2M_PLUGIN_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
