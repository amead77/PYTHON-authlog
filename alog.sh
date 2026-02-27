#!/usr/bin/env bash
set -u
set -o pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SESSION_NAME="${SESSION_NAME:-authlog2}"
CHECK_INTERVAL_SECONDS="${CHECK_INTERVAL_SECONDS:-60}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PYTHON_SCRIPT="${SCRIPT_DIR}/authlogger2.py"

log() {
    printf '[%(%Y-%m-%d %H:%M:%S)T] %s\n' -1 "$*"
}

require_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log "Missing required command: ${cmd}"
        exit 1
    fi
}

require_command tmux
require_command "$PYTHON_BIN"

if [[ ! -f "$PYTHON_SCRIPT" ]]; then
    log "Python script not found: ${PYTHON_SCRIPT}"
    exit 1
fi

cd -- "$SCRIPT_DIR" || {
    log "Failed to enter script directory: ${SCRIPT_DIR}"
    exit 1
}

build_python_command() {
    local -a cmd
    if [[ "${EUID}" -eq 0 ]]; then
        cmd=("$PYTHON_BIN" "$PYTHON_SCRIPT")
    elif command -v sudo >/dev/null 2>&1; then
        cmd=(sudo -n "$PYTHON_BIN" "$PYTHON_SCRIPT")
    else
        log "Not root and sudo is unavailable; cannot launch firewall writer safely."
        return 1
    fi

    printf '%q ' "${cmd[@]}"
}

while :; do
    if ! tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
        if launch_cmd="$(build_python_command)"; then
            log "Starting authlogger2.py in tmux session '${SESSION_NAME}'"
            if ! tmux new-session -d -s "$SESSION_NAME" -c "$SCRIPT_DIR" "$launch_cmd"; then
                log "Failed to create tmux session '${SESSION_NAME}'"
            fi
        else
            log "Launch command preparation failed; will retry in ${CHECK_INTERVAL_SECONDS}s"
        fi
    fi

    sleep "$CHECK_INTERVAL_SECONDS"
done