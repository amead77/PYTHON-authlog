#!/bin/bash

SESSION_NAME="authlog"

echo "Starting authlogger.py in tmux session '$SESSION_NAME'"

# Kill any existing session with the same name
tmux has-session -t $SESSION_NAME 2>/dev/null && tmux kill-session -t $SESSION_NAME

# Start the tmux session running the Python script
tmux new-session -d -s $SESSION_NAME "sudo python3 ~/Programming/PYTHON-authlog/authlogger.py"

echo "Session '$SESSION_NAME' started. You can attach with:"
echo "  tmux attach -t $SESSION_NAME"