/* FMADIO Ring Buffer Capture Plugin for Suricata
 * Copyright 2025-2026. Fidelis Farm & Technologies, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This plugin enables Suricata to capture packets from FMADIO devices
 * via their shared memory ring buffer interface.
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"
#include "conf.h"

#include "source.h"
#include "runmode.h"

/* Maximum number of ring buffers supported */
#define FMADIO_RING_MAX_RINGS 16

/* Global storage for ring buffer paths.
 * Populated from YAML config or --capture-plugin-args. */
static const char *fmadio_ring_paths[FMADIO_RING_MAX_RINGS];
static int fmadio_ring_count = 0;

/**
 * Get the number of configured ring buffers.
 * @return Number of rings (0 if none configured)
 */
int FmadioRingGetCount(void)
{
    return fmadio_ring_count;
}

/**
 * Get a ring buffer path by index.
 * @param index Ring index (0-based)
 * @return Ring path, or NULL if index out of range
 */
const char *FmadioRingGetPathByIndex(int index)
{
    if (index < 0 || index >= fmadio_ring_count) {
        return NULL;
    }
    return fmadio_ring_paths[index];
}

/**
 * Parse FMADIO ring configuration from YAML.
 * Looks for 'fmadio-ring' section with list of ring paths.
 *
 * Example YAML:
 *   fmadio-ring:
 *     - ring: /opt/fmadio/queue/lxc_ring0
 *     - ring: /opt/fmadio/queue/lxc_ring1
 *
 * @return Number of rings parsed, or 0 if no config found
 */
static int ParseFmadioRingConfig(void)
{
    SCConfNode *fmadio_node = SCConfGetNode("fmadio-ring");
    if (fmadio_node == NULL) {
        SCLogDebug("No fmadio-ring configuration found in YAML");
        return 0;
    }

    SCConfNode *ring_node;
    int count = 0;

    TAILQ_FOREACH(ring_node, &fmadio_node->head, next) {
        if (count >= FMADIO_RING_MAX_RINGS) {
            SCLogWarning("Maximum number of FMADIO rings (%d) exceeded",
                         FMADIO_RING_MAX_RINGS);
            break;
        }

        const char *ring_path = NULL;
        if (SCConfGetChildValue(ring_node, "ring", &ring_path) != 1) {
            SCLogWarning("FMADIO ring entry missing 'ring' key");
            continue;
        }

        if (ring_path == NULL || ring_path[0] == '\0') {
            SCLogWarning("FMADIO ring entry has empty path");
            continue;
        }

        SCLogNotice("Configured FMADIO ring %d: %s", count, ring_path);
        fmadio_ring_paths[count] = ring_path;
        count++;
    }

    return count;
}

/**
 * Initialize the capture plugin.
 * Called by Suricata when the plugin is selected via --capture-plugin.
 *
 * @param args Plugin arguments from --capture-plugin-args (ring buffer path)
 * @param plugin_slot Runmode slot (RUNMODE_PLUGIN)
 * @param receive_slot Thread module slot for receiver (TMM_RECEIVEPLUGIN)
 * @param decode_slot Thread module slot for decoder (TMM_DECODEPLUGIN)
 */
static void InitCapturePlugin(const char *args, int plugin_slot,
                               int receive_slot, int decode_slot)
{
    SCLogNotice("Initializing FMADIO Ring capture plugin");

    /* First try YAML configuration */
    int yaml_count = ParseFmadioRingConfig();

    if (yaml_count > 0) {
        fmadio_ring_count = yaml_count;
        SCLogNotice("Loaded %d ring(s) from YAML configuration", yaml_count);
    } else if (args != NULL && args[0] != '\0') {
        /* Fallback to command line args (single ring) */
        SCLogNotice("Using ring from --capture-plugin-args: %s", args);
        fmadio_ring_paths[0] = args;
        fmadio_ring_count = 1;
    } else {
        /* Use default path */
        SCLogNotice("Using default ring path: /opt/fmadio/queue/lxc_ring0");
        fmadio_ring_paths[0] = "/opt/fmadio/queue/lxc_ring0";
        fmadio_ring_count = 1;
    }

    /* Register runmodes (workers, single) */
    FmadioRingRunmodeRegister(plugin_slot);

    /* Register thread modules */
    TmModuleReceiveFmadioRingRegister(receive_slot);
    TmModuleDecodeFmadioRingRegister(decode_slot);
}

/**
 * Plugin initialization callback.
 * Called when the plugin shared library is loaded.
 */
static void SCPluginInit(void)
{
    SCLogNotice("Loading FMADIO Ring capture plugin");

    SCCapturePlugin *plugin = SCCalloc(1, sizeof(SCCapturePlugin));
    if (plugin == NULL) {
        FatalError("Failed to allocate memory for FMADIO Ring capture plugin");
    }

    plugin->name = "fmadio-ring";
    plugin->Init = InitCapturePlugin;
    plugin->GetDefaultMode = FmadioRingGetDefaultRunMode;

    SCPluginRegisterCapture(plugin);
}

/**
 * Plugin registration structure.
 * Must be named PluginRegistration and returned by SCPluginRegister().
 */
const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "fmadio-ring",
    .plugin_version = "0.1.0",
    .author = "Fidelis Farm & Technologies, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

/**
 * Plugin entry point.
 * Called by Suricata via dlsym() when the plugin is loaded.
 *
 * @return Pointer to the plugin registration structure
 */
const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
