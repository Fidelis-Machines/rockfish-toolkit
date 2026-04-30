/* Rockfish EtherNet/IP (CIP) Parser Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef ENIP_PLUGIN_H
#define ENIP_PLUGIN_H

#define ENIP_PLUGIN_VERSION "0.1.0"

/* Registration function (implemented in applayer.c) */
void EnipParserRegister(void);

#endif /* ENIP_PLUGIN_H */
