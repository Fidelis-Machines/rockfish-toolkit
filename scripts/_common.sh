# Fidelis Farm & Technologies, LLC / Copyright 2025-2026
#
# Shared helpers for rockfish-toolkit/scripts/ — sourced by every script.
#
# Sets:
#   TOOLKIT_DIR               — absolute path to /development/rockfish-toolkit
#   TOOLKIT_PROTO_PLUGINS_DIR — $TOOLKIT_DIR/suricata-proto-plugins
#   TOOLKIT_OUTPUT_PLUGIN_DIR — $TOOLKIT_DIR/suricata-output-plugin
#   TOOLKIT_FMADIO_PLUGIN_DIR — $TOOLKIT_DIR/suricata-plugin-fmadio-ring
#   TOOLKIT_SCRIPTS_DIR       — $TOOLKIT_DIR/scripts
#
# Usage in each script (after PROJECT_DIR is computed):
#   source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

if [ -z "${PROJECT_DIR:-}" ]; then
    echo "Error: PROJECT_DIR must be set before sourcing _common.sh" >&2
    return 1 2>/dev/null || exit 1
fi

_RESOLVED="$(cd "$PROJECT_DIR" 2>/dev/null && pwd -P)"
if [ -z "$_RESOLVED" ]; then
    echo "Error: cannot resolve PROJECT_DIR: $PROJECT_DIR" >&2
    return 1 2>/dev/null || exit 1
fi

case "$_RESOLVED" in
    */rockfish-toolkit)
        : # ok
        ;;
    *)
        echo "Error: rockfish-toolkit scripts must run inside /development/rockfish-toolkit" >&2
        echo "  Resolved PROJECT_DIR: $_RESOLVED" >&2
        return 1 2>/dev/null || exit 1
        ;;
esac

TOOLKIT_DIR="$_RESOLVED"
TOOLKIT_PROTO_PLUGINS_DIR="$TOOLKIT_DIR/suricata-proto-plugins"
TOOLKIT_OUTPUT_PLUGIN_DIR="$TOOLKIT_DIR/suricata-output-plugin"
TOOLKIT_FMADIO_PLUGIN_DIR="$TOOLKIT_DIR/suricata-plugin-fmadio-ring"
TOOLKIT_SCRIPTS_DIR="$TOOLKIT_DIR/scripts"
export TOOLKIT_DIR TOOLKIT_PROTO_PLUGINS_DIR TOOLKIT_OUTPUT_PLUGIN_DIR TOOLKIT_FMADIO_PLUGIN_DIR TOOLKIT_SCRIPTS_DIR

require_toolkit_path() {
    local target="$1"
    local abs
    abs="$(cd "$target" 2>/dev/null && pwd -P || echo "$target")"
    case "$abs" in
        "$TOOLKIT_DIR"|"$TOOLKIT_DIR"/*)
            : # ok
            ;;
        *)
            echo "Error: refusing to operate on path outside rockfish-toolkit: $target" >&2
            echo "       (resolved: $abs)" >&2
            exit 1
            ;;
    esac
}
export -f require_toolkit_path

export DUCKDB_LIB_DIR="${DUCKDB_LIB_DIR:-/usr/local/lib}"
