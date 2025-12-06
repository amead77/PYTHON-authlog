#!/bin/bash

SESSION_NAME="authlog"
PYTHON_SCRIPT="sudo python3 ~/Programming/PYTHON-authlog/authlogger.py"

while :; do
    if ! tmux has-session -t $SESSION_NAME 2>/dev/null; then
        echo "Starting authlogger.py in tmux session '$SESSION_NAME'"
        tmux new-session -d -s $SESSION_NAME "$PYTHON_SCRIPT"
    fi

    # Check every 60 seconds
    sleep 60
done