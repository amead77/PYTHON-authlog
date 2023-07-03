####################### [ About ] #######################
# This is a simple script to monitor the auth.log and vnc files for failed login attempts and block the IP address
# if the number of failed attempts is >= failcount.
#
# currently in use on my RPi because it's always connected and powered on. Every day people try to log in.
# at various points I've tried to implement keyboard input, but over shh (even with sshkeyboard)
# it breaks due to blocking input. curses can suck my dick as that solves one problem by introducing another.
#
# This came about because I didn't want to learn Fail2ban and wanted a real project to learn Python better.
# I am sure fail2ban is much more feature full and whatnot, but I didn't want a client-server setup, just
# a simple press-and-go script.
# Anyway, this does what I need it to do, keep out the bots trying default/popular passwords.
#
# the actual firewall rule setting is: 'iptables -I INPUT -s <IP> -j DROP'
#
# currently (as per below 3 lines from auth.log, 4th is vnc log) an invalid user can create a double match,
# as the system will log the invalid user, and the invalid password for invalid user. Not sure if I should
# adjust as f*** anyone trying dodgy names ;)
# Jun 28 03:26:42 whitebox sshd[776616]: Failed password for invalid user ubuntu from 118.36.15.126 port 61324 ssh2
# Jun 26 22:08:33 whitebox sshd[669886]: banner exchange: Connection from 192.241.236.62 port 34448: invalid format
# Jun 28 11:22:07 whitebox sshd[805578]: Invalid user wqmarlduiqkmgs from 60.205.111.35 port 57770
# Jun  7 12:52:40 whitebox sshd[2669317]: Unable to negotiate with 143.198.205.110 port 59296: no matching key exchange method found. Their offer: diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1 [preauth]
# <13> 2023-07-02T17:50:30.774Z whitebox vncserver-x11[551]: Connections: disconnected: 192.168.1.220::54605 (TCP) ([AuthFailure] Either the username was not recognised, or the password was incorrect)
####################### [ Requirements ] #######################

# Initially it only needs a few things.
# 1. either auth.log file, which is usually in /var/log/auth.log, or vncserver-x11.log, which is usually in /var/log/vncserver-x11.log
# 2. this file, run as sudo root.
# 3. iptables installed and running. (probably already installed on most linux distros)
# 4. oh, and Linux. You can test some of the code on Windows, but it won't actually do anything.
# 5. tmux or screen is recommended so you can run it in the background and detach the session.
#    I run it in a tmux session on my RPi, and I can ssh in and check the status of anytime I want by
#    attaching to the tmux session. Or I can look at the logfile from anywhere.
# 6. Python >= 3.10 due to match/case.
# 7. Check settings.ini if you want to change the default settings.

####################### [ To Do ] #######################
#
# TODO:
#   CHANGE: .ini should also contain the blocking rules.
#   CHANGE: Does it need to print to screen the whole list on startup (thousands of IPs in my case), or
#           just add a -v --verbose mode
#   CHANGE: maybe do the same to logging, logfile could end up hueg.
#   CHANGE: switch from configparser to toml, maybe, maybe not really needed.
#   CHANGE: I use so many globals in this, I should probably switch to local variables and pass to funcs.
#
####################### [ Changes ] #######################
# earlier wasn't noted... in fact I rarely noted changes, I really should.
# 2023-06-01 beginning to implement failcount, but not done yet
# 2023-06-18 pretty much done, tidying up in progress. wasn't much in libby.py so i merged it back in/
# 2023-06-25 added logging to see what is happening. suspect not correctly blocking new IPs, will see
# 2023-06-27 FIXED: not blocking new IPs, checking auth.log size changes was outside the loop, oops.
# 2023-06-28 FIXED: number of blocked IPs was incorrect by 1. added more auth error types to ScanAndCompare()
#                   also simplified ScanAndCompare()
# 2023-07-01 CHANGED: moving from cmdline args to .ini file for settings
# 2023-07-02 ADDED: beginning of implementing vnc log parsing. (scanandcompare() to work on finishing)
# 2023-07-03 CHANGED: opening logfiles as streams now split to check files exist and try..except to catch errors
# 2023-07-03 ADDED: settings.ini can now have multiple local IP addresses to ignore, separated by commas
####################### [ How this works ] #######################
# Reads /var/log/auth.log file, parses it very simply, creates an array of IP addresses along with a sub array of
# the datetime that they failed login.
# If the number of datetime entries is >= failcount, then send to IPTables to add to firewall rules.
#

####################### [ Code order ] #######################
# in simple terms the main order of code is:
# Create cBlock class, used as a record/struct
# create aBlocklist[] which becomes and array of cBlock class
# create aActiveBlocklist[] which is an array of IP addresses that are actually blocked.
# main() which is at the bottom
#   ClearScreen()
#   set ctrl-c detection
#   set global variables and check if running on linux, if not go into debug mode (doesn't actually send to iptables in debug mode)
#   OpenLogFile() to initialise the log file for sending data to (also prints to screen on logging)
#   Welcome() to show welcome text, duh..
#   GetArgs() to get command line arguments. Ignored now, loads ini file instead.
#   ClearIPTables() to clear out IPTables rules before setting any new ones
#   OpenBlocklist() to load the blocklist file into memory
#     FirstRunCheckBlocklist() to block any IPs already in the blocklist file if the number of datetime entries is >= failcount
#   PrintBlockList() to print the current blocklist to screen and log file
#   OpenLogFilesAsStream() to open the auth.log file as a stream, once opened stay in this function until ctrl-c
#      #Every time authlog gets new data, split it into lines and process each line by sending to ScanAndCompare()
#      #ScanAndCompare() checks if the line is a failed login attempt, if it is, it sends the IP to CheckBlocklist()
#    CheckBlocklist() checks if the IP is already in the blocklist aBlocklist[], if yes and unique, it adds the datetime to the cBlock object, else
#      #if the IP is not in the blocklist, it adds the IP to the aBlocklist[].
#      #if the number of datetime entries in the cBlock object of aBlocklist[] is >= failcount, it sends the IP to BlockIP()
#      BlockIP() sends the IP to iptables to be blocked, and adds the IP to aActiveBlocklist[] to keep track of what is currently blocked
#      #if Ctrl-C is detected, jump to: CloseGracefully()
# CloseGracefully() to close the auth.log stream and save the blocklist to file
#   SaveBlocklist() to save the blocklist aBlocklist[] to file
#   SaveSettings() to save the settings to ini file
#   CloseLogFile() to close the log file
#   assuming not in debug mode, save IPTables rules
#   ErrorArg()
# ErrorArg() to print error/exit message and exit
#

####################### [ Coding Style ] #######################
# I literally write this using camel case, snake case, pascal case, and whatever else I feel like at the time.
# I will try to adjust it for consistency.
#

#########################################################
####################### [ Setup ] #######################
#########################################################
#from getpass import getpass #not used anymore, should be run as sudo root, not try to elevate, as it's annoying
import os, argparse, sys, io, time, subprocess
import signal #for ctrl-c detection
import pickle #for saving blocklist
import datetime #for timestamping#
import configparser #for reading ini file
#import select #for keyboard input (os stdin)
#import readchar #for keyboard input (readchar.readkey())
#import curses #for keyboard input (curses.wrapper()) hopefully works over ssh

#from sshkeyboard import listen_keyboard, stop_listening

#import keyboard
#from subprocess import call

debugmode = False

version = "2023-07-03r0" #really need to update this every time I change something
#2023-02-12 21:37:26

# Initialize ncurses
#stdscr = curses.initscr()
#curses.noecho()
#curses.cbreak()
#stdscr.keypad(True)    
# Set nodelay mode to enable non-blocking input
#stdscr.nodelay(True)

class cBlock:
    def __init__(self, vDT=None, ip=None, vReason = None): #failcount not needed as count of datetime array will show failures
        self.aDateTime = []
        self.ip = ip
        self.aReason = []

    def add_datetime(self, vDT):
        self.aDateTime.append(vDT)

    def add_reason(self, vReason):
        self.aReason.append(vReason)

aBlocklist = [] #array of cBlock objects
aActiveBlocklist = [] #array of ip addresses
aIgnoreIPs = [] #array of ip addresses to ignore

#############################################################
####################### [ Functions ] #######################
#############################################################


#######################
def ClearScreen():
    #literally ask the OS to clear the screen
    if os.name == 'nt':  # for Windows
        os.system('cls')
    else:  # for Unix/Linux/MacOS
        os.system('clear')


#######################
def ErrorArg(err):
    #prints the error message and exits with the error code
    match err:
        case 0:
            print("bye!")
        case 1:
            print("no worries, bye!")
        case 2:
            Help()
        case 3:
            print("**NEEDS TO RUN AS (SUDO) ROOT, or it cannot access auth.log and set iptables rules")
            Help()
        case 4:
            print("got stuck in a loop")
        case 5:
            print("unable to create or write to logfile")
        case 6:
            print("settings.ini file not found.")
        case 7:
            print("auth.log file not found.")
        case 8:
            print("settings.ini failed to load correctly.")
        case 9:
            print("vnc log file not found.")
        case 10:
            print("neither auth.log nor vnc log file found/loaded.")
        case _:
            print("dunno, but bye!")
    sys.exit(err)


#######################
def CheckIsLinux():
    #this is because it is designed to run on Linux, but I also code on Windows, in which case I don't want it to run all the code
    if not sys.platform.startswith('linux'):
        debugmode = True
        return False
    else:
        return True


#######################
def Help():
    print("**something went wrong. I don't know what, it probably means a file didn't exist or you ran as a normie rather than root\n")
    print("Remember: must run as sudo/root or it cannot block IPs\n")


#######################
def Welcome():
    print('\n[==-- Wheel reinvention society presents: authlogger! --==]\n')
    print('Does some of what other, better, programs do, but worse!\n')
    print('Seriously, if you want to block IPs, use fail2ban, it\'s much better, but this is simpler...\n')
    print('version: '+version)
    print("To exit just crash out with ctrl-c, keyboard control over ssh is iffy.")
    

#######################
def GetArgs():
    LogData("getting args")
    global BlockFileName
    global AuthFileName
    global blockcount
    global localip
    global failcount
    global inifile
    global StartDir
    global slash
    #failure = False
#    loadsettingsstatus = False
#    parser = argparse.ArgumentParser()
#    parser.add_argument('-a', '--AuthFileName', action='store', help='auth.log file incl. path', default='/var/log/auth.log')
#    parser.add_argument('-b', '--BlockFileName', action='store', help='blocklist file, incl. path', default=StartDir+slash+'blocklist.txt')
#    parser.add_argument('-f', '--failcount', action='store', type=int, help='number of login failures to block IP (defaults to 2)', default=1)
#    parser.add_argument('-i', '--inifile', action='store', help='.ini file and path', default='')
#    parser.add_argument('-l', '--localip', action='store', help='local IP range to ignore (default 192.168.)', default='192.168.')
#    args = parser.parse_args()

    #load the ini file before anything else, so it can be overwritten by command line args
    #inifile = args.inifile
    #if inifile != '':
    #    loadsettingsstatus = LoadSettings()

    
    
#    if (args.AuthFileName != parser.get_default("AuthFileName")) or (loadsettingsstatus == False):
#        AuthFileName = args.AuthFileName

#    if (args.BlockFileName != parser.get_default("BlockFileName")) or (loadsettingsstatus == False):
#        BlockFileName = args.BlockFileName
    
#    if (args.localip != parser.get_default("localip")) or (loadsettingsstatus == False):
#        localip = args.localip

#    if (args.failcount != parser.get_default("failcount")) or (loadsettingsstatus == False):
#        failcount = args.failcount

#    if AuthFileName == '': ErrorArg(2)
#    if BlockFileName == '': ErrorArg(2)
#    if failcount < 1: ErrorArg(2)
#    if localip == '': ErrorArg(2)

    inifile = StartDir+slash+"settings.ini"
    if not os.path.isfile(inifile): ErrorArg(6)

    if not LoadSettings(): ErrorArg(8)

    if debugmode:
        AuthFileName = StartDir+slash+"auth.log"
    
    #if not os.path.isfile(AuthFileName): ErrorArg(7)

    #blockcount = FileLineCount(BlockFileName) #change this, no longer just a line per ip
    #authlinecount = FileLineCount(AuthFileName)


#######################
def PrintBlockList():
    global aBlocklist
    LogData('printing blocklist')
    for i in range(len(aBlocklist)):
        LogData(aBlocklist[i].ip+':')
        for x in range(len(aBlocklist[i].aDateTime)):
            LogData('-->'+ReverseDateTime(aBlocklist[i].aDateTime[x])+" reason: "+aBlocklist[i].aReason[x])


#######################
def CloseGracefully(signal=None, frame=None):
    LogData('closing...')
    #if ctrl-c is pressed, save iptables and exit
    global aBlocklist
    global AuthFileHandle
    global vncExists
    global authExists
    #AuthFileHandle.close() #not requred, as with statement closes it automatically
    LogData('closing streams')
    if vncExists: vncFileHandle.close()
    if authExists: AuthFileHandle.close()
    SaveBlockList()
    SaveSettings()
    CloseLogFile()
    if not debugmode:
        subprocess.call(['/sbin/iptables-save'])
    ErrorArg(0)


#######################
def BlockIP(ip):
    #the part that actually blocks the IP by sending details to iptables
    global debugmode
    global aActiveBlocklist

    #check if already blocked
    if ip in aActiveBlocklist:
        LogData('already blocked: '+ip)
        return
    else:
        if not debugmode:
            aActiveBlocklist.append(ip)
            LogData('Passing to IPTables ->'+ip)
            subprocess.call(['/sbin/iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'])
            #subprocess.call(['/sbin/iptables-save']) #has to save because no clean exit, update, now done in CloseGracefully()
        else:
            aActiveBlocklist.append(ip)
            LogData("ADD/debug mode: iptables -I INPUT -s "+ip+" -j DROP")


#######################
def FirstRunCheckBlocklist():
    #if first run, check aBlocklist for failures and add them to iptables
    global aBlocklist
    global failcount
    LogData('checking blocklist/first run: '+str(len(aBlocklist))+ ' entries')
    for x in range(0, len(aBlocklist)):
        if len(aBlocklist[x].aDateTime) >= failcount:
            #print('len(aBlocklist[x].aDateTime) '+str(len(aBlocklist[x].aDateTime)))
            BlockIP(aBlocklist[x].ip)
            #print('blocking: "'+aBlocklist[x].ip+'"')
    

#######################
def CheckBlocklist(ip, timeblocked, reason):
    #print('checking: '+ip)
    #check to see if ip is already in blocklist
    global aBlocklist
    foundit = False
    dtfound = -1
    for x in range(0, len(aBlocklist)):
        if aBlocklist[x].ip == ip:
            dtfound = x
            for y in range(0, len(aBlocklist[x].aDateTime)):
                if aBlocklist[x].aDateTime[y] == timeblocked:
                    foundit = True
                    break

    if not foundit:
        if dtfound >= 0:
            LogData('adding datetime: '+ip+' ['+reason+']')
            aBlocklist[dtfound].add_datetime(timeblocked)
            aBlocklist[dtfound].add_reason(reason)
            if len(aBlocklist[dtfound].aDateTime) >= failcount:
                BlockIP(ip)
        else:
            LogData('['+str(len(aBlocklist))+'] adding: '+ip+' ['+reason+']')
            aBlocklist.append(cBlock(ip=ip))
            aBlocklist[len(aBlocklist)-1].add_datetime(timeblocked)
            aBlocklist[len(aBlocklist)-1].add_reason(reason)
            if failcount == 1: #if failcount is 1, block on first failure
                BlockIP(ip)
        

#######################
def GetDateTime(authstring, authtype):
    match authtype:
        case 'auth.log':
            #get the date and time from the auth.log string, convert to YYYYMMDDHHMMSS
            #always use current year, as auth.log doesn't have year
            timey = time.strftime('%Y', time.localtime(time.time()))
            timey = time.strftime('%Y%m%d%H%M%S', time.strptime(timey+" "+authstring[:15], "%Y %b %d %H:%M:%S"))
        case 'vncserver-x11.log':
            #get the 2nd word in authstring, convert to YYYYMMDDHHMMSS
            timey = authstring.split()[1]
            timey = timey[:10]+' '+timey[11:19]
            timey = time.strftime('%Y%m%d%H%M%S', time.strptime(timey, "%Y-%m-%d %H:%M:%S"))
    return timey


#######################
def ReverseDateTime(authstring):
    #get the date and time in the format YYYYMMDDHHMMSS and convert to YYYY-MM-DD HH:MM:SS
    #this is only used for printing to the log file and screen.
    #the class cBlock uses the YYYYMMDDHHMMSS format, which was an oversight as YYYY-MM... would work fine, 
    #I could change it, but then I'd lose all my current saved IP's, so I'll leave it for now.
    timey = time.strftime('%Y-%m-%d %H:%M:%S', time.strptime(authstring, "%Y%m%d%H%M%S"))
    return timey


#######################
def ClearIPTables():
    #clear all iptables rules
    if not debugmode:
        LogData('clearing iptables')
        subprocess.call(['/sbin/iptables', '-F'])
        subprocess.call(['/sbin/iptables-save'])
        LogData('done')
    else:
        LogData("CLEAR/debug mode: iptables -F")


#######################
def ScanAndCompare(aline, authtype):
    global authstrings
    global blocklist
    global localip
    global failcount
    global aIgnoreIPs

    newblock = False
    #check if aline is in the array of aIgnoreIPs
    
    if not CheckLocalIP(aline):
    #if aline.find(localip) < 0: #don't do anything if it's the local ip
        match authtype:
            case 'auth.log':
                tmp = aline.split(' ') #split the line into an array
                if aline.find('Failed password for',) >= 0:
                    newblock = True
                    checkIP = tmp[len(tmp)-4]
                    
                if aline.find('Did not receive identification') >= 0:
                    newblock = True
                    checkIP = tmp[len(tmp)-3]

                if aline.find('Invalid user',) >= 0:
                    newblock = True
                    checkIP = tmp[len(tmp)-3]

                if (aline.find('banner exchange',) >= 0) and (aline.find('invalid format',) >= 0):
                    newblock = True
                    checkIP = tmp[len(tmp)-5]
                if newblock: CheckBlocklist(checkIP, GetDateTime(aline, authtype), '(auth.log) '+aline[16:])

                if (aline.find('Unable to negotiate',) >= 0) and (aline.find('diffie-hellman-group-exchange-sha1',) >= 0):
                    newblock = True
                    checkIP = tmp[9]
                if newblock: CheckBlocklist(checkIP, GetDateTime(aline, authtype), '(auth.log) '+aline[16:])

            case 'vncserver-x11.log':
                if aline.find('[AuthFailure]') >= 0:
                    newblock = True
                    tmp = aline.split(' ')
                    checkIP = tmp[6]
                    checkIP = checkIP.split('::')[0]
                if newblock: CheckBlocklist(checkIP, GetDateTime(aline, authtype), '(vncserver-x11.log) '+aline[30:])


#######################
def authModified():
    global authlogModtime
    global AuthFileName

    authModified = False

    if (os.path.isfile(AuthFileName)):
        if (os.path.getmtime(AuthFileName) != authlogModtime):
            authlogModtime = os.path.getmtime(AuthFileName)
            authModified = True
    else:
        LogData('auth.log file not found')
        ErrorArg(2)

    return authModified


#######################
def OpenBlockList():
    #print('opening blocklist')
    LogData('opening blocklist')
    #read in the blocklist file to aBlocklist array
    global aBlocklist
    global BlockFileName

    #aBlocklist = [] #should be the first time this is called. / wasn't though was it

    if (os.path.isfile(BlockFileName)):
        try:
            with open(BlockFileName, 'rb') as fblockfile:
                aBlocklist = pickle.load(fblockfile)
            #fblockfile.close() not required with 'with'
        except:
            #print('blocklist file is corrupt, will be overwritten on save')
            LogData('blocklist file is corrupt, will be overwritten on save')

    else:
        LogData('blocklist file not found, will be created on save')
    FirstRunCheckBlocklist()
        

#######################
def SaveBlockList():
    #print('saving blocklist (dump)')
    #save the blocklist array to the blocklist file
    global blocklist
    global BlockFileName

    LogData('saving blocklist')
    with open(BlockFileName, "wb") as fblockfile:
        pickle.dump(aBlocklist, fblockfile)
    #fblockfile.close() not required with 'with'


################################################################################################
# This is the main function loop, it reads the log file and calls ScanAndCompare for each line #
################################################################################################
def OpenLogFilesAsStream():
    LogData('opening logfiles as stream')
    global AuthFileName
    global AuthPos
    global AuthFileHandle
    global vncFileName
    global vncFileHandle
    global VNCPos
    global authExists
    global vncExists

    iFlush = 0 #flush log data every 10 seconds (approx)

    if (os.path.isfile(AuthFileName)):
        try:
            LogData('opening '+AuthFileName)
            AuthFileHandle = open(AuthFileName, 'r')
            authExists = True
        except:
            authExists = False
            LogData(AuthFileName+' error while loading')
    else:
        authExists = False
        LogData(AuthFileName+' file not found')
        #ErrorArg(2)

    if (os.path.isfile(vncFileName)):
        try:
            LogData('opening '+vncFileName)
            vncFileHandle = open(vncFileName, 'r')
            vncExists = True
        except:
            vncExists = False
            LogData(vncFileName+' error while loading')
    else:
        vncExists = False
        LogData(vncFileName+' file not found')
        #ErrorArg(2)
    
    if not (authExists and vncExists): ErrorArg(10) #if either file doesn't exist, exit, why else are we running?
    
    #
    # aahh.. problem. if one of the files doesn't exist, what then...?
    #
    #with open(AuthFileName, 'r') as AuthFileHandle, open(vncFileName, 'r') as vncFileHandle:
    while True:
        iFlush += 1
        if iFlush > 10: #flush log every 10 seconds, not immediately as slows things down
            iFlush = 0
            FlushLogFile()

        if authExists:
            alogsize = os.stat(AuthFileName).st_size
            # Check if the file size has changed

            #key = is_key_pressed()
            #if key == 'q':
            #    print("Escape key was pressed.")
            #    CloseGracefully()
            if alogsize > AuthPos:
                # Move the file pointer to the previous position
                AuthFileHandle.seek(AuthPos)
                # Read the new lines added to the file
                new_data = AuthFileHandle.read()
                
                # Process the new lines
                lines = new_data.split('\n')
                for line in lines:
                    ScanAndCompare(line, 'auth.log')
                        
                # Update the initial size to the current size
                AuthPos = alogsize
            elif alogsize < AuthPos: #log was rotated
                AuthPos = 0
        if vncExists:        
            vnclogsize = os.stat(vncFileName).st_size
            if vnclogsize > VNCPos:
                # Move the file pointer to the previous position
                vncFileHandle.seek(VNCPos)
                # Read the new lines added to the file
                new_data = vncFileHandle.read()
                
                # Process the new lines
                lines = new_data.split('\n')
                for line in lines:
                    ScanAndCompare(line, 'vncserver-x11.log')
                        
                # Update the initial size to the current size
                VNCPos = vnclogsize
            elif vnclogsize < VNCPos: #log was rotated
                VNCPos = 0

        time.sleep(1)
    #<--while True:

#######################
def SaveSettings():
    #save last settings to settings.ini
    global localip
    global BlockFileName
    global AuthFileName
    global failcount
    
    LogData('saving settings')
    # Create a new configparser object
    config = configparser.ConfigParser()
    # Set some example settings
    config['Settings'] = {
        'localip': localip,
        'blockfile': BlockFileName,
        'authfile': AuthFileName,
        'failcount': failcount,
        'vncfile': vncFileName
    }
    # Save the settings to an INI file
    try:
        with open('settings.ini', 'w') as configfile:
            config.write(configfile)
        configfile.close()
    except:
        LogData('error saving settings.ini')


#######################
def CheckLocalIP(CheckString):
    global aIgnoreIPs
    ret = False
    for i in range(len(aIgnoreIPs)):
        if aIgnoreIPs[i] in CheckString:
            ret = True
    return ret


#######################
def SplitLocalIP(ipList):
#split comma separated list of IPs into an array
    global aIgnoreIPs
    #aIgnoreIPs = ipList.split(',')
    #use list comprehension to split and strip the list
    aIgnoreIPs = [x.strip() for x in ipList.split(',')]
    
    LogData('local IP list: '+str(aIgnoreIPs))


#######################
def LoadSettings():
    # Load the settings from the INI file at startup, this will override the defaults, but not user set vars
    global localip
    global BlockFileName
    global AuthFileName
    global failcount
    global vncFileName
    
    LogData('loading settings')
    rt = False
    config = configparser.ConfigParser()
    try:
        config.read('settings.ini')
        # Access the settings
        localip = config.get('Settings','localip', fallback='192.168.')
        BlockFileName = config.get('Settings', 'blockfile', fallback = StartDir+slash+'blocklist.txt')
        AuthFileName = config.get('Settings', 'authfile', fallback = '/var/log/auth.log')
        fc = config.get('Settings','failcount', fallback= '2')
        failcount = int(fc)
        vncFileName = config.get('Settings','vncfile', fallback= StartDir+slash+'vncserver-x11.txt')
        # show me the settings
        LogData("loaded settings.ini:")
        LogData(f"localip(ini): {localip}")
        SplitLocalIP(localip)
        LogData(f"blockfile: {BlockFileName}")
        LogData(f"authfile: {AuthFileName}")
        LogData(f"failcount: {failcount}")
        LogData(f"vncfile: {vncFileName}")
        rt = True
    except:
        LogData('error loading settings.ini')
        rt = False
    return rt


#######################
def OpenLogFile():
    global LogFileName
    global logFileHandle
    global slash
    if not os.path.isdir(StartDir + slash + 'logs'):
        os.mkdir(StartDir + slash + 'logs')
    LogFileName = StartDir + slash + 'logs' + slash + 'authlogger.log'
    try:
        logFileHandle = open(LogFileName, 'a')
    except:
        print('error opening logfile')
        ErrorArg(5)
    logFileHandle.write('authlogger started.\n')


#######################
def LogData(sdata):
    #write timestamp+sdata to logfile, then flush to disk
    global logFileHandle
    print('['+TimeStamp()+']:'+sdata)
    logFileHandle.write('['+TimeStamp()+']:'+sdata + '\n')
    #logFileHandle.flush()


#######################
def TimeStamp():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))


#######################
def CloseLogFile():
    global logFileHandle
    LogData('authlogger stopped.\n')
    logFileHandle.close()


#######################
def FlushLogFile():
    global logFileHandle
    logFileHandle.flush()


########################################################
####################### [ MAIN ] #######################
########################################################
def main():
    
    ClearScreen()
    
    global localip
    global StartDir
    global blockcount
    global BlockFileName
    global AuthFileName
    global debugmode
    global AuthPos
    global AuthFileHandle
    global LogFileName
    global vncFileName
    global vncFileHandle
    global VNCPos
    VNCPos = 0
    AuthPos = 0
    global slash
    slash = '/'
    signal.signal(signal.SIGINT, CloseGracefully) #ctrl-c detection


    if not CheckIsLinux():
        print("not linux, so going into debug mode")
        slash = '\\'
        debugmode = True
        
    rebuild = False
    StartDir = os.getcwd().removesuffix(slash)
    OpenLogFile()
    Welcome()
    GetArgs()
    time.sleep(3)
    ClearIPTables()
    #no longer use try...except...finally, as it was causing issues with ctrl-c, errors should be caught in the functions
    #try:
    OpenBlockList()
    PrintBlockList()
    OpenLogFilesAsStream()
    #except:
        #print('error in main()')
    #finally:

    #should never reach here due to ctrl-c detection
    CloseGracefully()
    ErrorArg(0)
    sys.exit(255)

if __name__ == '__main__':
    main()   
