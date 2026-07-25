/* Fidelis Farm & Technologies, LLC EtherCAT Parser Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"

#include "ethercat-plugin.h"

extern void EthercatParserRegister(void);

static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish EtherCAT parser plugin");

    SCAppLayerPlugin plugin = {
        .name = "ethercat",
        .Register = EthercatParserRegister,
        .KeywordsRegister = NULL,
        .logname = "ethercat",
        .confname = "ethercat",
        .dir = 0,
        .Logger = NULL,
    };
    SCPluginRegisterAppLayer(&plugin);
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-ethercat-parser",
    .plugin_version = ETHERCAT_PLUGIN_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
