# PYTHON-authlog

## parses the auth.log and/or vnc log files and adds failed access to IPTables rules.

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


If testing on Windows, put a auth.log or vncserver-x11.log file in the same directory, as on windows it goes to debug mode and uses local files for testing without trying iptables.

Example logging data kept in logs/authlogger.log

```

[2023-08-20 06:35:59]:[7] adding: 85.95.117.176 [(auth.log) whitebox sshd[615634]: banner exchange: Connection from 85.95.117.176 port 57083: invalid format]
[2023-08-20 06:35:59]:saving blocklist
[2023-08-20 06:37:40]:adding datetime: [7] 85.95.117.176 [(auth.log) whitebox sshd[615704]: Invalid user NL5xUDpV2xRa from 85.95.117.176 port 59445]
[2023-08-20 06:37:40]:Autoblock bad user: NL5XUDPV2XRA
[2023-08-20 06:37:40]:Passing to IPTables ->85.95.117.176
[2023-08-20 06:37:41]:saving blocklist
```


In the above, first someone attempts to connect at 06:35:59 but the formats don't match, so it gets added to the list of failures (in this case, IP number 7), along with the reason.

Blocklist (containing the just mentioned) gets saved.

Same IP again tries at 06:37:40, this time the format is correct but they use a commonly used username (NL5XUDPV2XRA) that often tries access. This username is in my list of autoblockusers in settings.ini

Because of this the IP gets automatically blocked regardless of the number of login failures permitted.
