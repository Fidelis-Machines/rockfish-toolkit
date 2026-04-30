/* Rockfish CANopen Parser Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef CANOPEN_PLUGIN_H
#define CANOPEN_PLUGIN_H

#define CANOPEN_PLUGIN_VERSION "0.1.0"

/* Registration function (implemented in applayer.c) */
void CanopenParserRegister(void);

#endif /* CANOPEN_PLUGIN_H */
