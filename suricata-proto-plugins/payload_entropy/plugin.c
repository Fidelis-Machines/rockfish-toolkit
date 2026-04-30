/* Rockfish Suricata Payload Entropy Plugin
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Computes Shannon entropy of payload bytes per flow per direction.
 * Useful for detecting:
 *   - Encrypted exfiltration (high entropy ~7.9-8.0 bits/byte)
 *   - Ransomware payload encryption
 *   - Compressed traffic vs plaintext
 *   - DGA-like random subdomain encoding
 *
 * Emits one `payload_entropy` event per flow termination via Suricata's
 * eve-log subsystem. Enable under suricata.yaml eve-log.types: [payload_entropy].
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"
#include "conf.h"

#include "payload-entropy.h"

static void SCPluginInit(void)
{
    SCLogNotice("Loading Rockfish Payload Entropy plugin v%s",
                ROCKFISH_PAYLOAD_ENTROPY_VERSION);
    RockfishPayloadEntropyRegister();
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "rockfish-payload-entropy",
    .plugin_version = ROCKFISH_PAYLOAD_ENTROPY_VERSION,
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
