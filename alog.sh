#while :;
#do
#    echo "Starting authlogger.py"
#    tmux -c "sudo python authlogger.py"
#    #if not exit on code 12, then exit, else restart
#    #sudo python authlogger.py
#    if [ $? -ne 12 ]; then
#        echo "authlogger.py exited with code $?, exiting..."
#        exit
#    fi
#    
#    echo "authlogger.py exited, waiting 5 seconds before restarting..."
#    echo "Press Ctrl+C to exit"
#    sleep 5
#done

#!/bin/bash

while :; do
    echo "Starting authlogger.py"
    tmux new-session -d -s authlog "sudo python /path/to/authlogger.py"

    # Wait for the tmux session to end
    tmux wait-for -S authlog_done
    tmux kill-session -t authlog

    # Check exit code (you'll need to pass it from Python if needed)
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 12 ]; then
        echo "authlogger.py exited with code $EXIT_CODE, exiting..."
        exit
    fi

    echo "authlogger.py exited, waiting 5 seconds before restarting..."
    echo "Press Ctrl+C to exit"
    sleep 5
done