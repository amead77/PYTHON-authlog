#!/bin/bash

SESSION_NAME="authlog"

while :; do
    echo "Starting authlogger.py in tmux session '$SESSION_NAME'"

    # Kill any existing session with the same name
    tmux has-session -t $SESSION_NAME 2>/dev/null && tmux kill-session -t $SESSION_NAME

    # Start the tmux session running the Python script
    tmux new-session -d -s $SESSION_NAME "sudo python3 ~/Programming/PYTHON-authlog/authlogger.py"

    # Wait for the session to end
    while tmux has-session -t $SESSION_NAME 2>/dev/null; do
        sleep 1
    done

    # Optionally: check exit code if you log it from Python
    # For now, assume restart only on code 12
    EXIT_CODE=12  # Placeholder

    if [ $EXIT_CODE -ne 12 ]; then
        echo "authlogger.py exited with code $EXIT_CODE, exiting..."
        exit
    fi

    echo "authlogger.py exited, waiting 5 seconds before restarting..."
    echo "Press Ctrl+C to exit"
    sleep 5
done