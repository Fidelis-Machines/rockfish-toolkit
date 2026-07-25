/* Fidelis Farm & Technologies, LLC CoAP Parser Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"

#include "coap-plugin.h"

extern void CoapParserRegister(void);

static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish CoAP parser plugin");

    SCAppLayerPlugin plugin = {
        .name = "coap",
        .Register = CoapParserRegister,
        .KeywordsRegister = NULL,
        .logname = "coap",
        .confname = "coap",
        .dir = 0,
        .Logger = NULL,
    };
    SCPluginRegisterAppLayer(&plugin);
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-coap-parser",
    .plugin_version = COAP_PLUGIN_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
