#!/bin/bash

while :
do
    echo "Starting authlogger.py"
    tmux -c "sudo python authlogger.py"
    #if not exit on code 12, then exit, else restart
    if [ $? -ne 12 ]; then
        echo "authlogger.py exited with code $?, exiting..."
        exit
    fi
    
    echo "authlogger.py exited, waiting 5 seconds before restarting..."
    echo "Press Ctrl+C to exit"
    sleep 5
done

