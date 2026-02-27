# PYTHON-authlog

## parses the auth.log and/or vnc/kern.log log files and adds failed access to IPTables rules.

My RPi is on 24/7 and connected to the net.

### It gets a LOT of failed password attempts.

GPLv3 Licence, see copying.txt

If you're not willing to live on the edge, go use fail2ban, it is probably more suitable anyway.

 This is a simple script to monitor the auth.log and vnc files for failed login attempts and block the IP address
 if the number of failed attempts is >= failcount.

  
 This came about because I didn't want to learn Fail2ban and wanted a real project to learn Python better.
 I am sure fail2ban is much more feature full and whatnot, but I didn't want a client-server setup, just
 a simple press-and-go script.
 Anyway, this does what I need it to do, keep out the bots trying default/popular passwords.
  
 Initially it only needs a few things.
 1. either auth.log file, which is usually in /var/log/auth.log, or vncserver-x11.log, which is usually in /var/log/vncserver-x11.log
 2. this file, run as sudo root.
 3. iptables installed and running. (probably already installed on most linux distros)
 4. oh, and Linux. You can test some of the code on Windows, but it won't actually do anything.
 5. tmux or screen is recommended so you can run it in the background and detach the session.
    I run it in a tmux session on my RPi, and I can ssh in and check the status of anytime I want by
    attaching to the tmux session. Or I can look at the logfile from anywhere.
 6. Python >= 3.10 due to match/case.
 7. Check settings.ini if you want to change the default settings.

## Installing

## On Raspberry Pi:

for authlogger.py raspberry pi os no longer creates auth.log or includes iptables.
To enable auth.log file and Iptables..

1. apt install rsyslog
2. systemctl enable rsyslog
3. apt install iptables
4. apt install tmux


If using my startup script along with tmux and you want it to start on boot, use "crontab -e" and add the following line (edit to suit your system):
```
@reboot /home/adam/Documents/Programming/PYTHON-authlog/alog.sh >> /home/adam/Documents/Programming/PYTHON-authlog/alog.log 2>&1
```

## check paths in settings.ini and alog.sh

You don't have to use tmux, but tmux means you can start it in the background and it doesn't close if you disconnect. To connect to the running tmux console, use "tmux attach", to disconnect use "ctrl-b, d".

If testing on Windows, put a auth.log or vncserver-x11.log file in the same directory, as on windows it goes to debug mode and uses local files for testing without trying iptables.

