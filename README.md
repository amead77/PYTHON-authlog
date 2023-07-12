# PYTHON-authlog

## parses the auth.log and/or vnc log files and adds failed access to IPTables rules.

My RPi is on 24/7 and connected to the net.

### It gets a LOT of failed password attempts.

If you're not willing to live on the edge, go use fail2ban, it is probably more suitable anyway.

 This is a simple script to monitor the auth.log and vnc files for failed login attempts and block the IP address
 if the number of failed attempts is >= failcount.

 currently in use on my RPi because it's always connected and powered on. Every day people try to log in.
 at various points I've tried to implement keyboard input, but over shh (even with sshkeyboard)
 it breaks due to blocking input. curses can suck my dick as that solves one problem by introducing another.

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
