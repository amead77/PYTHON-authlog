# PYTHON-authlog

## parses the auth.log file and adds failed access to IPTables rules.

My RPi is on 24/7 and connected to the net.


### It gets a LOT of failed password attempts.


Anyway, I was looking at things like fail2ban and other stuff, then decided it would be easy to implement something really simple.

All it needs to do is update rules...

Anyway, over time it grew, as things do. Still use it on my RPi and get shocked by how many failed logins I get. 
I delete the blocklist file every now and then because it gets so big.

Do as you want, or not, with this. It was never meant to be used as anything other than a plaything/learning experience.

I run this through tmux so I can monitor it whenever I connect, but should also work through cron without issue.
