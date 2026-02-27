# PYTHON-authlog

## parses the auth.log and/or vnc (vnc support connectly disabled) log files and adds failed access to IPTables rules.

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

1> apt install rsyslog
2> systemctl enable rsyslog
3> apt install iptables
4> apt install tmux

If using my startup script along with tmux and you want it to start on boot, use "crontab -e" and add the following line (edit to suit your system):

@reboot /home/adam/Documents/Programming/PYTHON-authlog/alog.sh >> /home/adam/Documents/Programming/PYTHON-authlog/alog.log 2>&1

## check paths in settings.ini and alog.sh

You don't have to use tmux, but tmux means you can start it in the background and it doesn't close if you disconnect. To connect to the running tmux console, use "tmux attach", to disconnect use "ctrl-b, d".

If testing on Windows, put a auth.log or vncserver-x11.log file in the same directory, as on windows it goes to debug mode and uses local files for testing without trying iptables.

Example logging data kept in logs/authlogger.log below, showing a typical startup with existing blocks in place. First it runs it's startup routines, then blocks autoblocks IPs in it's blocklist based on the rules, then prints out a verbose list of everything in the blocklist.

```

[2023-08-25 22:26:55]:authlogger started.
[2023-08-25 22:26:55]:clearing iptables
[2023-08-25 22:26:55]:done
[2023-08-25 22:26:55]:getting args
[2023-08-25 22:26:55]:loading settings
[2023-08-25 22:26:55]:reading settings.ini
[2023-08-25 22:26:55]:loaded settings.ini:
[2023-08-25 22:26:55]:autoblock users: ADMIN,ROOT,PI,NL5XUDPV2XRA,EC2-USER,ADMINISTRATOR,UBUNTU,WEBADMIN,VNCUSER,VSFTP,USER,FTP,FTPUSER,MYSQL
[2023-08-25 22:26:55]:localip(ini): 192.168., 10.0.
[2023-08-25 22:26:55]:local IP list: ['192.168.', '10.0.']
[2023-08-25 22:26:55]:blockfile: /home/adam/authlog/blocklist.dat
[2023-08-25 22:26:55]:authfile: /var/log/auth.log
[2023-08-25 22:26:55]:vncfile: /var/log/vncserver-x11.log
[2023-08-25 22:26:55]:failcount: 3
[2023-08-25 22:26:55]:restart_time: 20:33:00
[2023-08-25 22:26:58]:opening blocklist
[2023-08-25 22:26:58]:checking blocklist/first run: 77 entries
[2023-08-25 22:26:58]:Passing to IPTables ->159.223.137.47 reason: bad user: mysql
[2023-08-25 22:26:58]:Passing to IPTables ->193.201.9.108 reason: bad user: admin
[2023-08-25 22:26:58]:Passing to IPTables ->139.59.68.177 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->80.66.66.177 reason: reason: 3 login failures from this IP
[2023-08-25 22:26:58]:Passing to IPTables ->193.201.9.109 reason: bad user: admin
[2023-08-25 22:26:58]:Passing to IPTables ->52.56.224.130 reason: reason: 3 login failures from this IP
[2023-08-25 22:26:58]:Passing to IPTables ->18.134.246.89 reason: reason: 3 login failures from this IP
[2023-08-25 22:26:58]:Passing to IPTables ->18.170.74.132 reason: reason: 3 login failures from this IP
[2023-08-25 22:26:58]:Passing to IPTables ->202.185.181.42 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->167.172.190.187 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->62.74.208.58 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->191.252.93.173 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->45.184.44.149 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->103.3.61.10 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->157.230.178.64 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->121.190.22.245 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->160.251.55.50 reason: bad user: admin
[2023-08-25 22:26:58]:Passing to IPTables ->167.99.89.165 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->50.215.29.170 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->71.128.32.25 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->185.233.36.187 reason: reason: 3 login failures from this IP
[2023-08-25 22:26:58]:Passing to IPTables ->173.249.187.22 reason: reason: 3 login failures from this IP
[2023-08-25 22:26:58]:Passing to IPTables ->85.208.253.130 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->185.231.59.173 reason: reason: 3 login failures from this IP
[2023-08-25 22:26:58]:Passing to IPTables ->68.168.142.91 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->42.200.66.164 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->203.172.76.4 reason: bad user: admin
[2023-08-25 22:26:58]:Passing to IPTables ->49.231.241.23 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->103.143.230.237 reason: bad user: user
[2023-08-25 22:26:58]:Passing to IPTables ->24.199.113.153 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->222.118.223.15 reason: bad user: admin
[2023-08-25 22:26:58]:Passing to IPTables ->210.91.254.26 reason: bad user: user
[2023-08-25 22:26:58]:Passing to IPTables ->139.59.68.172 reason: bad user: root
[2023-08-25 22:26:58]:Passing to IPTables ->72.176.181.35 reason: bad user: root
[2023-08-25 22:26:58]:printing blocklist
[2023-08-25 22:26:58]:[0] 118.123.105.93:
[2023-08-25 22:26:58]:-->2023-08-20 00:56:20 - u=[] reason: (auth.log) whitebox sshd[601191]: banner exchange: Connection from 118.123.105.93 port 53642: invalid format
[2023-08-25 22:26:58]:[1] 159.223.137.47:
[2023-08-25 22:26:58]:-->2023-08-20 01:15:38 - u=[mysql] reason: (auth.log) whitebox sshd[601953]: Failed password for invalid user mysql from 159.223.137.47 port 33392 ssh2
[2023-08-25 22:26:58]:-->2023-08-20 01:27:43 - u=[mysql] reason: (auth.log) whitebox sshd[602363]: Failed password for invalid user mysql from 159.223.137.47 port 33168 ssh2
[2023-08-25 22:26:58]:[2] 193.201.9.108:
[2023-08-25 22:26:58]:-->2023-08-20 01:21:52 - u=[admin] reason: (auth.log) whitebox sshd[602150]: Failed password for invalid user admin from 193.201.9.108 port 14522 ssh2
[2023-08-25 22:26:58]:[3] 67.198.242.130:
[2023-08-25 22:26:58]:-->2023-08-20 02:53:36 - u=[] reason: (auth.log) whitebox sshd[605850]: banner exchange: Connection from 67.198.242.130 port 49810: invalid format
[2023-08-25 22:26:58]:[4] 191.97.55.254:
[2023-08-25 22:26:58]:-->2023-08-20 04:22:40 - u=[] reason: (auth.log) whitebox sshd[609643]: banner exchange: Connection from 191.97.55.254 port 56024: invalid format
[2023-08-25 22:26:58]:[5] 107.170.247.15:
[2023-08-25 22:26:58]:-->2023-08-20 05:03:03 - u=[] reason: (auth.log) whitebox sshd[611203]: banner exchange: Connection from 107.170.247.15 port 37826: invalid format
[2023-08-25 22:26:58]:[6] 39.96.117.34:
[2023-08-25 22:26:58]:-->2023-08-20 05:17:26 - u=[] reason: (auth.log) whitebox sshd[611836]: banner exchange: Connection from 39.96.117.34 port 53159: invalid format
[2023-08-25 22:26:58]:[7] 85.95.117.176:
[2023-08-25 22:26:58]:-->2023-08-20 06:35:59 - u=[] reason: (auth.log) whitebox sshd[615634]: banner exchange: Connection from 85.95.117.176 port 57083: invalid format
[2023-08-25 22:26:58]:[8] 47.106.143.44:
[2023-08-25 22:26:58]:-->2023-08-20 12:13:29 - u=[] reason: (auth.log) whitebox sshd[631771]: banner exchange: Connection from 47.106.143.44 port 54976: invalid format
[2023-08-25 22:26:58]:[9] 47.251.56.197:
[2023-08-25 22:26:58]:-->2023-08-20 12:36:46 - u=[] reason: (auth.log) whitebox sshd[633183]: banner exchange: Connection from 47.251.56.197 port 51262: invalid format
[2023-08-25 22:26:58]:[10] 8.218.128.142:
[2023-08-25 22:26:58]:-->2023-08-20 12:47:59 - u=[] reason: (auth.log) whitebox sshd[633710]: banner exchange: Connection from 8.218.128.142 port 54742: invalid format
[2023-08-25 22:26:58]:[11] 139.59.68.177:
[2023-08-25 22:26:58]:-->2023-08-20 22:00:17 - u=[root] reason: (auth.log) whitebox sshd[29216]: Failed password for root from 139.59.68.177 port 54808 ssh2
[2023-08-25 22:26:58]:[12] 192.155.90.118:
[2023-08-25 22:26:58]:-->2023-08-21 00:46:40 - u=[] reason: (auth.log) whitebox sshd[36484]: banner exchange: Connection from 192.155.90.118 port 34110: invalid format
[2023-08-25 22:26:58]:-->2023-08-22 05:16:47 - u=[] reason: (auth.log) whitebox sshd[121325]: banner exchange: Connection from 192.155.90.118 port 16972: invalid format
[2023-08-25 22:26:58]:[13] 177.105.117.219:
[2023-08-25 22:26:58]:-->2023-08-21 02:17:40 - u=[] reason: (auth.log) whitebox sshd[40395]: banner exchange: Connection from 177.105.117.219 port 34831: invalid format
[2023-08-25 22:26:58]:[14] 192.241.231.49:
[2023-08-25 22:26:58]:-->2023-08-21 03:12:01 - u=[] reason: (auth.log) whitebox sshd[43308]: banner exchange: Connection from 192.241.231.49 port 37884: invalid format
[2023-08-25 22:26:58]:[15] 108.170.78.226:
[2023-08-25 22:26:58]:-->2023-08-21 03:27:00 - u=[] reason: (auth.log) whitebox sshd[43818]: banner exchange: Connection from 108.170.78.226 port 36841: invalid format
[2023-08-25 22:26:58]:[16] 117.50.3.179:
[2023-08-25 22:26:58]:-->2023-08-21 10:01:36 - u=[] reason: (auth.log) whitebox sshd[63253]: banner exchange: Connection from 117.50.3.179 port 36426: invalid format
[2023-08-25 22:26:58]:[17] 80.66.66.177:
[2023-08-25 22:26:58]:-->2023-08-21 10:11:20 - u=[] reason: (auth.log) whitebox sshd[64110]: banner exchange: Connection from 80.66.66.177 port 64967: invalid format
[2023-08-25 22:26:58]:-->2023-08-21 10:13:03 - u=[] reason: (auth.log) whitebox sshd[64157]: banner exchange: Connection from 80.66.66.177 port 64153: invalid format
[2023-08-25 22:26:58]:-->2023-08-21 10:14:46 - u=[] reason: (auth.log) whitebox sshd[64225]: banner exchange: Connection from 80.66.66.177 port 63905: invalid format
[2023-08-25 22:26:58]:[18] 103.56.61.132:
[2023-08-25 22:26:58]:-->2023-08-21 10:46:31 - u=[] reason: (auth.log) whitebox sshd[65483]: banner exchange: Connection from 103.56.61.132 port 52338: invalid format
[2023-08-25 22:26:58]:[19] 45.79.181.179:
[2023-08-25 22:26:58]:-->2023-08-21 11:02:28 - u=[] reason: (auth.log) whitebox sshd[66449]: banner exchange: Connection from 45.79.181.179 port 33134: invalid format
[2023-08-25 22:26:58]:[20] 47.93.222.233:
[2023-08-25 22:26:58]:-->2023-08-21 11:16:50 - u=[] reason: (auth.log) whitebox sshd[67369]: banner exchange: Connection from 47.93.222.233 port 36316: invalid format
[2023-08-25 22:26:58]:[21] 193.201.9.109:
[2023-08-25 22:26:58]:-->2023-08-21 14:43:28 - u=[admin] reason: (auth.log) whitebox sshd[77879]: Failed password for invalid user admin from 193.201.9.109 port 19556 ssh2
[2023-08-25 22:26:58]:[22] 121.142.56.91:
[2023-08-25 22:26:58]:-->2023-08-21 15:29:49 - u=[] reason: (auth.log) whitebox sshd[80441]: banner exchange: Connection from 121.142.56.91 port 31999: invalid format
[2023-08-25 22:26:58]:[23] 109.205.213.94:
[2023-08-25 22:26:58]:-->2023-08-21 18:01:04 - u=[] reason: (auth.log) whitebox sshd[88278]: banner exchange: Connection from 109.205.213.94 port 34540: invalid format
[2023-08-25 22:26:58]:[24] 52.56.224.130:
[2023-08-25 22:26:58]:-->2023-08-21 18:23:48 - u=[] reason: (auth.log) whitebox sshd[89735]: banner exchange: Connection from 52.56.224.130 port 21045: invalid format
[2023-08-25 22:26:58]:-->2023-08-21 18:23:50 - u=[] reason: (auth.log) whitebox sshd[89736]: banner exchange: Connection from 52.56.224.130 port 21045: invalid format
[2023-08-25 22:26:58]:-->2023-08-21 18:23:51 - u=[] reason: (auth.log) whitebox sshd[89737]: banner exchange: Connection from 52.56.224.130 port 21045: invalid format
[2023-08-25 22:26:58]:[25] 18.134.246.89:
[2023-08-25 22:26:58]:-->2023-08-21 19:07:06 - u=[] reason: (auth.log) whitebox sshd[92481]: banner exchange: Connection from 18.134.246.89 port 21107: invalid format
[2023-08-25 22:26:58]:-->2023-08-21 19:07:11 - u=[] reason: (auth.log) whitebox sshd[92484]: banner exchange: Connection from 18.134.246.89 port 32794: invalid format
[2023-08-25 22:26:58]:-->2023-08-21 19:07:22 - u=[] reason: (auth.log) whitebox sshd[92485]: banner exchange: Connection from 18.134.246.89 port 50626: invalid format
[2023-08-25 22:26:58]:[26] 18.170.74.132:
[2023-08-25 22:26:58]:-->2023-08-21 20:12:06 - u=[] reason: (auth.log) whitebox sshd[95981]: banner exchange: Connection from 18.170.74.132 port 21402: invalid format
[2023-08-25 22:26:58]:-->2023-08-21 20:12:08 - u=[] reason: (auth.log) whitebox sshd[95983]: banner exchange: Connection from 18.170.74.132 port 21402: invalid format
[2023-08-25 22:26:58]:-->2023-08-21 20:12:14 - u=[] reason: (auth.log) whitebox sshd[95985]: banner exchange: Connection from 18.170.74.132 port 34356: invalid format
[2023-08-25 22:26:58]:[27] 8.218.252.70:
[2023-08-25 22:26:58]:-->2023-08-22 00:24:20 - u=[] reason: (auth.log) whitebox sshd[108000]: banner exchange: Connection from 8.218.252.70 port 36678: invalid format
[2023-08-25 22:26:58]:[28] 152.89.198.113:
[2023-08-25 22:26:58]:-->2023-08-22 00:59:49 - u=[] reason: (auth.log) whitebox sshd[109519]: banner exchange: Connection from 152.89.198.113 port 61350: invalid format
[2023-08-25 22:26:58]:-->2023-08-22 09:48:01 - u=[] reason: (auth.log) whitebox sshd[133703]: banner exchange: Connection from 152.89.198.113 port 64532: invalid format
[2023-08-25 22:26:58]:[29] 192.241.215.54:
[2023-08-25 22:26:58]:-->2023-08-22 01:21:20 - u=[] reason: (auth.log) whitebox sshd[110795]: banner exchange: Connection from 192.241.215.54 port 36748: invalid format
[2023-08-25 22:26:58]:[30] 192.241.203.52:
[2023-08-25 22:26:58]:-->2023-08-22 03:28:25 - u=[] reason: (auth.log) whitebox sshd[116418]: banner exchange: Connection from 192.241.203.52 port 37232: invalid format
[2023-08-25 22:26:58]:[31] 118.193.36.11:
[2023-08-25 22:26:58]:-->2023-08-22 04:11:31 - u=[] reason: (auth.log) whitebox sshd[118017]: banner exchange: Connection from 118.193.36.11 port 31600: invalid format
[2023-08-25 22:26:58]:[32] 58.220.24.40:
[2023-08-25 22:26:58]:-->2023-08-22 06:51:36 - u=[] reason: (auth.log) whitebox sshd[125389]: banner exchange: Connection from 58.220.24.40 port 17264: invalid format
[2023-08-25 22:26:58]:[33] 8.134.73.126:
[2023-08-25 22:26:58]:-->2023-08-23 02:44:42 - u=[] reason: (auth.log) whitebox sshd[184131]: banner exchange: Connection from 8.134.73.126 port 47928: invalid format
[2023-08-25 22:26:58]:[34] 45.79.181.104:
[2023-08-25 22:26:58]:-->2023-08-23 08:12:14 - u=[] reason: (auth.log) whitebox sshd[198369]: banner exchange: Connection from 45.79.181.104 port 30796: invalid format
[2023-08-25 22:26:58]:[35] 91.191.209.202:
[2023-08-25 22:26:58]:-->2023-08-23 08:47:41 - u=[] reason: (auth.log) whitebox sshd[200141]: banner exchange: Connection from 91.191.209.202 port 63882: invalid format
[2023-08-25 22:26:58]:[36] 120.25.168.240:
[2023-08-25 22:26:58]:-->2023-08-23 11:20:01 - u=[] reason: (auth.log) whitebox sshd[206933]: banner exchange: Connection from 120.25.168.240 port 36334: invalid format
[2023-08-25 22:26:58]:[37] 161.189.42.18:
[2023-08-25 22:26:58]:-->2023-08-23 15:39:39 - u=[] reason: (auth.log) whitebox sshd[220129]: banner exchange: Connection from 161.189.42.18 port 44612: invalid format
[2023-08-25 22:26:58]:[38] 183.136.225.5:
[2023-08-25 22:26:58]:-->2023-08-23 20:04:14 - u=[] reason: (auth.log) whitebox sshd[234931]: banner exchange: Connection from 183.136.225.5 port 44892: invalid format
[2023-08-25 22:26:58]:[39] 202.185.181.42:
[2023-08-25 22:26:58]:-->2023-08-23 20:10:49 - u=[root] reason: (auth.log) whitebox sshd[235242]: Failed password for root from 202.185.181.42 port 50314 ssh2
[2023-08-25 22:26:58]:[40] 167.172.190.187:
[2023-08-25 22:26:58]:-->2023-08-23 20:11:24 - u=[root] reason: (auth.log) whitebox sshd[235270]: Failed password for root from 167.172.190.187 port 33792 ssh2
[2023-08-25 22:26:58]:[41] 62.74.208.58:
[2023-08-25 22:26:58]:-->2023-08-23 20:12:12 - u=[root] reason: (auth.log) whitebox sshd[235340]: Failed password for root from 62.74.208.58 port 33962 ssh2
[2023-08-25 22:26:58]:[42] 191.252.93.173:
[2023-08-25 22:26:58]:-->2023-08-23 20:12:13 - u=[root] reason: (auth.log) whitebox sshd[235342]: Failed password for root from 191.252.93.173 port 41008 ssh2
[2023-08-25 22:26:58]:[43] 45.184.44.149:
[2023-08-25 22:26:58]:-->2023-08-23 20:12:22 - u=[root] reason: (auth.log) whitebox sshd[235346]: Failed password for root from 45.184.44.149 port 38274 ssh2
[2023-08-25 22:26:58]:[44] 103.3.61.10:
[2023-08-25 22:26:58]:-->2023-08-23 20:13:44 - u=[root] reason: (auth.log) whitebox sshd[235451]: Failed password for root from 103.3.61.10 port 54478 ssh2
[2023-08-25 22:26:58]:[45] 157.230.178.64:
[2023-08-25 22:26:58]:-->2023-08-23 20:13:55 - u=[root] reason: (auth.log) whitebox sshd[235454]: Failed password for root from 157.230.178.64 port 36424 ssh2
[2023-08-25 22:26:58]:[46] 121.190.22.245:
[2023-08-25 22:26:58]:-->2023-08-23 20:14:01 - u=[root] reason: (auth.log) whitebox sshd[235457]: Failed password for root from 121.190.22.245 port 46076 ssh2
[2023-08-25 22:26:58]:[47] 160.251.55.50:
[2023-08-25 22:26:58]:-->2023-08-23 20:18:24 - u=[admin] reason: (auth.log) whitebox sshd[235673]: Failed password for invalid user admin from 160.251.55.50 port 46248 ssh2
[2023-08-25 22:26:58]:[48] 167.99.89.165:
[2023-08-25 22:26:58]:-->2023-08-23 20:30:13 - u=[cacti] reason: (auth.log) whitebox sshd[236195]: Failed password for invalid user cacti from 167.99.89.165 port 35832 ssh2
[2023-08-25 22:26:58]:-->2023-08-23 20:33:05 - u=[root] reason: (auth.log) whitebox sshd[236336]: Failed password for root from 167.99.89.165 port 42088 ssh2
[2023-08-25 22:26:58]:[49] 50.215.29.170:
[2023-08-25 22:26:58]:-->2023-08-23 20:58:41 - u=[root] reason: (auth.log) whitebox sshd[237760]: Failed password for root from 50.215.29.170 port 43932 ssh2
[2023-08-25 22:26:58]:[50] 71.128.32.25:
[2023-08-25 22:26:58]:-->2023-08-23 21:06:46 - u=[root] reason: (auth.log) whitebox sshd[238137]: Failed password for root from 71.128.32.25 port 42194 ssh2
[2023-08-25 22:26:58]:[51] 185.233.36.187:
[2023-08-25 22:26:58]:-->2023-08-23 21:14:23 - u=[csadmin] reason: (auth.log) whitebox sshd[238505]: Failed password for invalid user csadmin from 185.233.36.187 port 41436 ssh2
[2023-08-25 22:26:58]:-->2023-08-23 21:18:03 - u=[maryam] reason: (auth.log) whitebox sshd[239013]: Failed password for invalid user maryam from 185.233.36.187 port 40368 ssh2
[2023-08-25 22:26:58]:-->2023-08-23 21:19:59 - u=[peter] reason: (auth.log) whitebox sshd[239160]: Failed password for invalid user peter from 185.233.36.187 port 47772 ssh2
[2023-08-25 22:26:58]:[52] 173.249.187.22:
[2023-08-25 22:26:58]:-->2023-08-23 21:15:10 - u=[easy] reason: (auth.log) whitebox sshd[238531]: Failed password for invalid user easy from 173.249.187.22 port 53906 ssh2
[2023-08-25 22:26:58]:-->2023-08-23 21:21:07 - u=[halo] reason: (auth.log) whitebox sshd[239185]: Failed password for invalid user halo from 173.249.187.22 port 54492 ssh2
[2023-08-25 22:26:58]:-->2023-08-23 21:25:30 - u=[root] reason: (auth.log) whitebox sshd[239468]: Failed password for root from 173.249.187.22 port 39538 ssh2
[2023-08-25 22:26:58]:[53] 85.208.253.130:
[2023-08-25 22:26:58]:-->2023-08-23 21:15:11 - u=[root] reason: (auth.log) whitebox sshd[238820]: Failed password for root from 85.208.253.130 port 56854 ssh2
[2023-08-25 22:26:58]:[54] 185.231.59.173:
[2023-08-25 22:26:58]:-->2023-08-23 21:18:37 - u=[maryam] reason: (auth.log) whitebox sshd[239016]: Failed password for invalid user maryam from 185.231.59.173 port 60284 ssh2
[2023-08-25 22:26:58]:-->2023-08-23 21:24:35 - u=[nec] reason: (auth.log) whitebox sshd[239389]: Failed password for invalid user nec from 185.231.59.173 port 60356 ssh2
[2023-08-25 22:26:58]:-->2023-08-23 21:24:48 - u=[root] reason: (auth.log) whitebox sshd[239392]: Failed password for root from 185.231.59.173 port 60360 ssh2
[2023-08-25 22:26:58]:[55] 68.168.142.91:
[2023-08-25 22:26:58]:-->2023-08-23 21:19:46 - u=[vbg] reason: (auth.log) whitebox sshd[239107]: Failed password for invalid user vbg from 68.168.142.91 port 37158 ssh2
[2023-08-25 22:26:58]:-->2023-08-23 21:25:00 - u=[root] reason: (auth.log) whitebox sshd[239417]: Failed password for root from 68.168.142.91 port 54212 ssh2
[2023-08-25 22:26:58]:[56] 42.200.66.164:
[2023-08-25 22:26:58]:-->2023-08-23 21:26:14 - u=[root] reason: (auth.log) whitebox sshd[239495]: Failed password for root from 42.200.66.164 port 35724 ssh2
[2023-08-25 22:26:58]:[57] 203.172.76.4:
[2023-08-25 22:26:58]:-->2023-08-23 21:27:28 - u=[admin] reason: (auth.log) whitebox sshd[239542]: Failed password for invalid user admin from 203.172.76.4 port 53662 ssh2
[2023-08-25 22:26:58]:[58] 49.231.241.23:
[2023-08-25 22:26:58]:-->2023-08-23 21:27:45 - u=[root] reason: (auth.log) whitebox sshd[239545]: Failed password for root from 49.231.241.23 port 51754 ssh2
[2023-08-25 22:26:58]:[59] 103.143.230.237:
[2023-08-25 22:26:58]:-->2023-08-23 21:28:36 - u=[user] reason: (auth.log) whitebox sshd[239614]: Failed password for invalid user user from 103.143.230.237 port 47952 ssh2
[2023-08-25 22:26:58]:[60] 24.199.113.153:
[2023-08-25 22:26:58]:-->2023-08-23 21:29:23 - u=[lyj] reason: (auth.log) whitebox sshd[239640]: Failed password for invalid user lyj from 24.199.113.153 port 56004 ssh2
[2023-08-25 22:26:58]:-->2023-08-23 21:31:50 - u=[root] reason: (auth.log) whitebox sshd[240097]: Failed password for root from 24.199.113.153 port 40988 ssh2
[2023-08-25 22:26:58]:[61] 192.241.236.73:
[2023-08-25 22:26:58]:-->2023-08-23 22:07:12 - u=[] reason: (auth.log) whitebox sshd[243328]: banner exchange: Connection from 192.241.236.73 port 47546: invalid format
[2023-08-25 22:26:58]:[62] 172.105.128.11:
[2023-08-25 22:26:58]:-->2023-08-24 05:18:44 - u=[] reason: (auth.log) whitebox sshd[262259]: banner exchange: Connection from 172.105.128.11 port 4680: invalid format
[2023-08-25 22:26:58]:[63] 222.118.223.15:
[2023-08-25 22:26:58]:-->2023-08-24 07:33:42 - u=[admin] reason: (auth.log) whitebox sshd[268528]: Failed password for invalid user admin from 222.118.223.15 port 34508 ssh2
[2023-08-25 22:26:58]:[64] 37.97.239.52:
[2023-08-25 22:26:58]:-->2023-08-24 07:40:26 - u=[] reason: (auth.log) whitebox sshd[268905]: banner exchange: Connection from 37.97.239.52 port 45322: invalid format
[2023-08-25 22:26:58]:[65] 107.155.56.246:
[2023-08-25 22:26:58]:-->2023-08-24 13:53:36 - u=[] reason: (auth.log) whitebox sshd[287050]: banner exchange: Connection from 107.155.56.246 port 51872: invalid format
[2023-08-25 22:26:58]:[66] 84.54.51.54:
[2023-08-25 22:26:58]:-->2023-08-24 17:44:52 - u=[] reason: (auth.log) whitebox sshd[298406]: banner exchange: Connection from 84.54.51.54 port 47736: invalid format
[2023-08-25 22:26:58]:[67] 170.106.176.49:
[2023-08-25 22:26:58]:-->2023-08-24 18:28:08 - u=[] reason: (auth.log) whitebox sshd[300701]: banner exchange: Connection from 170.106.176.49 port 53690: invalid format
[2023-08-25 22:26:58]:[68] 210.91.254.26:
[2023-08-25 22:26:58]:-->2023-08-24 18:32:19 - u=[user] reason: (auth.log) whitebox sshd[300840]: Failed password for invalid user user from 210.91.254.26 port 42677 ssh2
[2023-08-25 22:26:58]:[69] 201.70.52.10:
[2023-08-25 22:26:58]:-->2023-08-24 20:00:15 - u=[] reason: (auth.log) whitebox sshd[305161]: banner exchange: Connection from 201.70.52.10 port 49639: invalid format
[2023-08-25 22:26:58]:[70] 139.59.68.172:
[2023-08-25 22:26:58]:-->2023-08-24 21:55:22 - u=[root] reason: (auth.log) whitebox sshd[311041]: Failed password for root from 139.59.68.172 port 52934 ssh2
[2023-08-25 22:26:58]:[71] 47.242.93.118:
[2023-08-25 22:26:58]:-->2023-08-24 21:55:38 - u=[] reason: (auth.log) whitebox sshd[311067]: banner exchange: Connection from 47.242.93.118 port 45312: invalid format
[2023-08-25 22:26:58]:[72] 198.199.96.98:
[2023-08-25 22:26:58]:-->2023-08-24 22:50:41 - u=[] reason: (auth.log) whitebox sshd[313250]: banner exchange: Connection from 198.199.96.98 port 36630: invalid format
[2023-08-25 22:26:58]:[73] 72.176.181.35:
[2023-08-25 22:26:58]:-->2023-08-24 23:41:09 - u=[root] reason: (auth.log) whitebox sshd[315358]: Failed password for root from 72.176.181.35 port 35840 ssh2
[2023-08-25 22:26:58]:[74] 172.104.11.4:
[2023-08-25 22:26:58]:-->2023-08-25 05:11:29 - u=[] reason: (auth.log) whitebox sshd[328761]: banner exchange: Connection from 172.104.11.4 port 26782: invalid format
[2023-08-25 22:26:58]:[75] 36.170.39.167:
[2023-08-25 22:26:58]:-->2023-08-25 08:53:23 - u=[] reason: (auth.log) whitebox sshd[338520]: banner exchange: Connection from 36.170.39.167 port 28264: invalid format
[2023-08-25 22:26:58]:[76] 47.242.68.56:
[2023-08-25 22:26:58]:-->2023-08-25 08:57:23 - u=[] reason: (auth.log) whitebox sshd[338639]: banner exchange: Connection from 47.242.68.56 port 56530: invalid format
[2023-08-25 22:26:58]:opening logfiles as stream
[2023-08-25 22:26:58]:opening /var/log/auth.log
[2023-08-25 22:26:58]:opening /var/log/vncserver-x11.log
```

