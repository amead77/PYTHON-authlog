# PYTHON-authlog

## parses the auth.log file and adds failed access to IPTables rules.

My RPi is on 24/7 and connected to the net.


### It gets a LOT of failed password attempts.

Read authlogger.py, all is explained in the comments.
If you're not willing to live on the edge, go use fail2ban, it is probably more suitable anyway.