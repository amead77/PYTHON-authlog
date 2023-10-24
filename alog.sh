#!/bin/bash
#this doesn't work and I don't know why, sudo ./alog.sh works fine
#from cmd line, but not when being called by tmux -c
while :
do
    echo "Starting authlogger.py"
    #tmux -c "sudo python authlogger.py"
    #if not exit on code 12, then exit, else restart
    sudo python authlogger.py
    if [ $? -ne 12 ]; then
        echo "authlogger.py exited with code $?, exiting..."
        exit
    fi
    
    echo "authlogger.py exited, waiting 5 seconds before restarting..."
    echo "Press Ctrl+C to exit"
    sleep 5
done

