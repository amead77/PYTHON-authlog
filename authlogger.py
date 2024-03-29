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
# currently (as per below 3 lines from auth.log, 5th is vnc log) an invalid user can create a double match,
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
#   CHANGE: could do with splitting out the scan parts so that instead of hard coded positional search, it
#           a list of search terms and positions to look for. perhaps a list read from a file.
#   CHANGE: Does it need to print to screen the whole list on startup (thousands of IPs in my case), or
#           just add a -v --verbose mode
#   CHANGE: maybe do the same to logging, logfile could end up hueg.
#   CHANGE: switch from configparser to toml, maybe, maybe not really needed.
#   CHANGE: I use so many globals in this, I should probably switch to local variables and pass to funcs.
#   CHANGE: there's a lot of hard coded text, probably should move to a file so translations are possible.
#   CHANGE: see FirstRunCheckBlocklist() for TODO: block specific users
#

####################### [ Changes ] #######################
# earlier wasn't noted... in fact I rarely noted changes, I really should.
# 2020 - 2023: I don't remember what I did, but it was a lot. Which hardly any remains of, and is unhelpful to even bother mentioning...
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
# 2023-07-09 CHANGED: exception: to exception Exception as e: to catch all non fatals.
# 2023-07-11 FIXED: date string read from log could cause ctd if not in correct format. Now substitutes with 2001-01-01 00:00:00
# 2023-07-11 ADDED: some more exception handling, removed some globals.
# 2023-07-12 CHANGED: cleaning up, checking for possible exceptions.
# 2023-07-12 ADDED: -n/--nolog option to not log to file, just print to screen.
# 2023-07-12 CHANGED: if adding a new block, updates the blocklist file (within 10s) rather than waiting for ctrl-c
# 2023-07-16 FIXED: blocklist update delay was not working, now fixed.
# 2023-07-28 ADDED: sigterm handler to close gracefully on shutdown, I hope.
# 2023-07-30 ADDED: when adding a datetime to existing IP, show which array index it is.
# 2023-08-06 ADDED: restart time, so it can be restarted at a specific time of day. (in conjunction with bash script looping it)
#                   This is because I noticed some weirdness with the log file, seems after some days it just stopped blocking.
#                   Restarting it every day should fix that until I know why.
# 2023-08-06 CHANGED: split OpenLogFilesAsStream() into 4 funcs, OpenAuthAsStream(), OpenVNCAsStream(), CheckAuthLog(), CheckVNCLog()
# 2023-08-08 FIXED: I hope... CheckAuthLog() and CheckVNCLog() were checking if log was cycled, but not closing/reopening the stream, just resetting the position.
#                   Now closes/reopens the stream if log is cycled. I'll change the reset time to a nil value to test for a few days.
# 2023-08-10 ADDED: AmAlive() added to print a timestamp to log every hour to show it's still functioning
# 2023-08-10 ADDED: Auto block specific users, such as root, pi... (see settings.ini) - DISABLED due to I've screwed up.
# 2023-08-19 FIXED: log rotation checking error. noticed file pos was being reset to zero on every check
# 2023-08-20 FIXED: auto block users fixed. also no longer overwrites settings.ini on exit, only if it doesn't exist.
# 2023-08-25 CHANGED: more verbose in blocking IPs, some more exception handling.

####################### [ How this works ] #######################
# Reads /var/log/auth.log file, parses it very simply, creates an array of IP addresses along with a sub array of
# the datetime that they failed login.
# If the number of datetime entries is >= failcount, then send to IPTables to add to firewall rules.
#


####################### [ Coding Style ] #######################
# I literally write this using camel case, snake case, pascal case, and whatever else I feel like at the time.
# I will try to adjust it for consistency.
#



#########################################################
####################### [ Setup ] #######################
#########################################################
#from getpass import getpass #not used anymore, should be run as sudo root, not try to elevate, as it's annoying
import errno
import os, argparse, sys, io, time, subprocess
import signal #for ctrl-c detection
import pickle #for saving blocklist
import datetime #for timestamping#
import configparser #for reading ini file
#import select #for keyboard input (os stdin)
#import readchar #for keyboard input (readchar.readkey())
#import curses #for keyboard input (curses.wrapper()) hopefully works over ssh

#from sshkeyboard import listen_keyboard, stop_listening
import gzip #these two for gzipping the log file
import shutil


debugmode = False
#version should now be auto-updated by version_update.py. Do not manually change except the major/minor version. Next comment req. for auto-update
#AUTO-V
version = "v1.0-2023/11/02r00"

class cBlock:
    def __init__(self, vDT=None, ip=None, vReason = None, vUsername = None): #failcount not needed as count of datetime array will show failures
        self.aDateTime = []
        self.ip = ip
        self.aReason = []
        self.aUsername = []

    def add_datetime(self, vDT):
        self.aDateTime.append(vDT)

    def add_reason(self, vReason):
        self.aReason.append(vReason)
    
    def add_username(self, vUsername):
        self.aUsername.append(vUsername)

aBlocklist = [] #array of cBlock objects
aActiveBlocklist = [] #array of ip addresses
aIgnoreIPs = [] #array of ip addresses to ignore
aAutoBlockUsers = [] #array of users to auto block, such as root, pi, etc

#############################################################
####################### [ Functions ] #######################
#############################################################


#######################
def ClearScreen():
    #literally ask the OS to clear the screen
    if os.name == 'nt':  # for Windows
        os.system('cls')
    else:  # for Linux
        os.system('clear')


#######################
def ErrorArg(err):
    #prints the error message and exits with the error code
    #
    # maybe change this to read from file, so it can be translated?
    #
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
        case 11:
            print("for some reason, end of main() was reached. This should not have happened :(")
        case 12:
            print("Exiting because restart time is met.") 
        case 13:
            print("Ctrl-C detected, exiting gracefully.") #need to figure out how to pass from signal
        case 14:
            print("Shutdown demanded")
        case 15:
            print("Error creating logfile directory.")
        case _:
            print("dunno, but bye!")
    sys.exit(err)


#######################
def CheckIsLinux():
    #this is because it is designed to run on Linux, but I also code on Windows, in which case I don't want it to run all the code
    #I don't have a mac so I don't know what is needed for mac (other than /)
    global debugmode
    global slash

    if not sys.platform.startswith('linux'):
        slash = '\\'
        debugmode = True
        print("not running on linux, debug mode enabled")


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
    print("To EXIT use CTRL-C.")
    

#######################
def GetArgs():
    #ok, most of this got removed when i switched to using an ini file.
    #it remains in case I want to switch back to using command line args
    LogData("getting args")

    global iniFileName
    global StartDir
    global slash
    global Logging
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--nolog', action='store_false', help='turn off logging to disk')
    args = parser.parse_args()
    Logging = args.nolog
    iniFileName = StartDir+slash+"settings.ini"
    if not LoadSettings(): ErrorArg(8)


#######################
def PrintBlockList():
    #literally prints out the current blocklist contents
    global aBlocklist
    LogData('printing blocklist')
    for i in range(len(aBlocklist)):
        LogData('['+str(i)+'] '+aBlocklist[i].ip+':')
        for x in range(len(aBlocklist[i].aDateTime)):
            LogData('-->'+ReverseDateTime(aBlocklist[i].aDateTime[x])+" - u=["+aBlocklist[i].aUsername[x]+"] reason: "+aBlocklist[i].aReason[x])


#######################
def SaveIPTables():
    subprocess.call(['/sbin/iptables-save'])


#######################
def CloseGracefully(signal=None, frame=None, exitcode=0):
    #if ctrl-c is pressed, save iptables and exit
    LogData('closing...')
    global aBlocklist
    global AuthFileHandle
    global vncExists
    global authExists
    #AuthFileHandle.close() #not requred, as with statement closes it automatically
    LogData('closing streams')
    if vncExists and (exitcode != 10): vncFileHandle.close()
    if authExists and (exitcode != 10): AuthFileHandle.close()
    SaveBlockList()
    SaveSettings()
    CloseLogFile()
    if not debugmode: SaveIPTables()
    if exitcode is not None: ErrorArg( exitcode )


#######################
def BlockIP(ip, reason=''):
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
            LogData('Passing to IPTables ->'+ip+' reason: '+reason)
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
        if (len(aBlocklist[x].aDateTime) >= failcount):
            #print('len(aBlocklist[x].aDateTime) '+str(len(aBlocklist[x].aDateTime)))
            BlockIP(aBlocklist[x].ip, 'reason: '+str(len(aBlocklist[x].aDateTime))+' login failures from this IP')
            #print('blocking: "'+aBlocklist[x].ip+'"')
        else:
            for y in range(0, len(aBlocklist[x].aUsername)):
                if CheckAutoBlockUsers(aBlocklist[x].aUsername[y]):
                    BlockIP(aBlocklist[x].ip, 'bad user: '+aBlocklist[x].aUsername[y])
                    break


#######################
def IsValidIP(ip):
    #check if ip is valid ipv4 address
    ret = False
    if ip.count('.') == 3:
        tmp = ip.split('.')
        if len(tmp) == 4:
            for x in range(len(tmp)):
                #why this not work?
                #ret = True if tmp[x].isnumeric() else False; break
                if tmp[x].isnumeric():
                    ret = True
                else:
                    ret = False
                    break
    return ret


#######################
def CheckBlocklist(ip, timeblocked, reason, user=''):
    #print('checking: '+ip)
    #check to see if ip is already in blocklist
    global aBlocklist
    foundit = False
    dtfound = -1
    
    if not IsValidIP(ip): 
        return

    for x in range(0, len(aBlocklist)):
        if aBlocklist[x].ip == ip:
            dtfound = x
            for y in range(0, len(aBlocklist[x].aDateTime)):
                if aBlocklist[x].aDateTime[y] == timeblocked:
                    foundit = True
                    break

    if not foundit:
        if (dtfound >= 0):
            LogData('adding datetime: ['+str(dtfound)+'] '+ip+' u=['+user+'] r=['+reason+']')
            aBlocklist[dtfound].add_datetime(timeblocked)
            aBlocklist[dtfound].add_reason(reason)
            aBlocklist[dtfound].add_username(user)
            if CheckAutoBlockUsers(user): 
                BlockIP(ip, 'bad user: '+user)
            elif (len(aBlocklist[dtfound].aDateTime) >= failcount): 
                BlockIP(ip, 'failcount: '+str(len(aBlocklist[dtfound].aDateTime))+' login failures from this IP')
            #if (len(aBlocklist[dtfound].aDateTime) >= failcount) or (CheckAutoBlockUsers(user)):
            #    BlockIP(ip)
        else:
            LogData('['+str(len(aBlocklist))+'] adding: '+ip+' u=['+user+'] r=['+reason+']')
            aBlocklist.append(cBlock(ip=ip))
            aBlocklist[len(aBlocklist)-1].add_datetime(timeblocked)
            aBlocklist[len(aBlocklist)-1].add_reason(reason)
            aBlocklist[len(aBlocklist)-1].add_username(user)
            if CheckAutoBlockUsers(user): 
                BlockIP(ip, 'bad user: '+user)
            elif (failcount == 1): 
                BlockIP(ip, 'failcount: login failures set to 1')

            #if (failcount == 1) or (CheckAutoBlockUsers(user)): #if failcount is 1, block on first failure
            #    BlockIP(ip)
    foundit = True if not foundit else False
    if debugmode and foundit: print("CBL-foundit")
    return foundit

#######################
def GetDateTime(authstring, authtype):
    match authtype:
        case 'auth.log':
            #get the date and time from the auth.log string, convert to YYYYMMDDHHMMSS
            #always use current year, as auth.log doesn't have year
            try:
                timey = time.strftime('%Y', time.localtime(time.time()))
                timey = time.strftime('%Y%m%d%H%M%S', time.strptime(timey+" "+authstring[:15], "%Y %b %d %H:%M:%S"))
            except:
                timey = "20000101000000"
    
        case 'vncserver-x11.log':
            #get the 2nd word in authstring, convert to YYYYMMDDHHMMSS
            try:
                timey = authstring.split()[1]
                timey = timey[:10]+' '+timey[11:19]
                timey = time.strftime('%Y%m%d%H%M%S', time.strptime(timey, "%Y-%m-%d %H:%M:%S"))
            except:
                print('error: '+authstring+'--'+authtype)
                timey = "20000101000000"

    return timey


#######################
def AmAlive():
    #print out a timestamp to log every hour to show it's still functioning
    global LastCheckIn

    nowtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    #print just the hour from nowtime variable
    if (nowtime[-5:-3] == '00') and (nowtime[-8:-6] != LastCheckIn):
        LastCheckIn = nowtime[-8:-6]
        LogData('Checking in, nothing to report')


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
    #global AuthPos
    DateString = ''
    newblock = False
    username = ''
    #check if aline is in the array of aIgnoreIPs
    
    if not CheckLocalIP(aline):
    #if aline.find(localip) < 0: #don't do anything if it's the local ip
        match authtype:
            case 'auth.log':
                tmp = aline.split(' ') #split the line into an array

                if aline.find(': Failed password for invalid user') >= 0:
                    newblock = True
                    checkIP = tmp[len(tmp)-4]
                    username = tmp[len(tmp)-6]

                elif aline.find(': Failed password for') >= 0:
                    newblock = True
                    checkIP = tmp[len(tmp)-4]
                    username = tmp[len(tmp)-6]
                
                elif aline.find('Did not receive identification') >= 0:
                    newblock = True
                    checkIP = tmp[len(tmp)-3]

                elif (aline.find('banner exchange') >= 0) and (aline.find('invalid format',) >= 0):
                    newblock = True
                    checkIP = tmp[len(tmp)-5]

                elif (aline.find('Unable to negotiate') >= 0) and (aline.find('diffie-hellman-group-exchange-sha1',) >= 0):
                    newblock = True
                    checkIP = tmp[9]

                elif (aline.find('(sshd:auth): authentication failure;') >= 0):
                    newblock = True
                    if aline.find(' user=') >= 0:
                        checkIP = tmp[len(tmp)-3]
                        username = tmp[len(tmp)-1]
                    else: 
                        username = 'none'
                        checkIP = tmp[len(tmp)-1]
                  
                if newblock: PassMe = '(auth.log) '+aline[16:]
                #if newblock: CheckBlocklist(checkIP, DateString, '(auth.log:'+str(AuthPos) +') '+aline[16:])

            case 'vncserver-x11.log':
                if aline.find('[AuthFailure]') >= 0:
                    newblock = True
                    tmp = aline.split(' ')
                    checkIP = tmp[6]
                    checkIP = checkIP.split('::')[0]
                
                if newblock: PassMe = '(vncserver-x11.log) '+aline[30:]
                #if newblock: CheckBlocklist(checkIP, DateString, '(vncserver-x11.log:'+str(AuthPos) +') '+aline[30:])
        if newblock:
            DateString = GetDateTime(aline, authtype)
            newblock = CheckBlocklist(checkIP, DateString, PassMe, user=username)
            if debugmode:
                if newblock: print("SAC-newblock")
    return newblock

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
        except Exception as e:
            print('Exception: ', e)
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
        fblockfile.flush()
    #fblockfile.close() not required with 'with'


#######################
def CheckRestartTime():
    #if current time is equal o restart_time, exist the script (bash will restart it)
    global restart_time
    global debugmode
    
    #now = datetime.datetime.now()
    ntime = time.strftime('%H:%M:%S', time.localtime(time.time()))
    #ntime = str(now.hour)+':'+str(now.minute)+':'+str(now.second)
    if ntime == restart_time:
        LogData('restarting at '+ntime)
        #if not debugmode:
        #    CloseGracefully(exitcode=12)
        #else:
        #    print('RESTART/debug mode: restarting at '+ntime)
        CloseGracefully(exitcode=12) if not debugmode else print('RESTART/debug mode: restarting at '+ntime)

#######################
def OpenAuthAsStream():
    #opens the auth.log file as a stream
    global AuthFileName
    global AuthPos
    global AuthFileHandle
    global authExists
    global AuthLogInode

    AuthPos = 0
    try:
        LogData('opening '+AuthFileName)
        AuthFileHandle = open(AuthFileName, 'r')
        AuthLogInode = get_file_inode(AuthFileName)
        authExists = True
    except Exception as e:
        authExists = False
        print('Exception: ', e)
        LogData(AuthFileName+' error while loading, exception: '+str(e))


#######################
def OpenVNCAsStream():
    #opens the vncserver-x11.log file as a stream
    global vncFileName
    global VNCPos
    global vncFileHandle
    global vncExists
    global VNCLogInode

    VNCPos = 0
    try:
        LogData('opening '+vncFileName)
        vncFileHandle = open(vncFileName, 'r')
        VNCLogInode = get_file_inode(vncFileName)
        vncExists = True
    except Exception as e:
        vncExists = False
        print('Exception: ', e)
        LogData(vncFileName+' error while loading, exception: '+str(e)) 


#######################
def CloseAuthStream():
    #closes the auth.log file stream
    global AuthFileName
    global AuthPos
    global AuthFileHandle
    global authExists

    try:
        LogData('closing '+AuthFileName)
        AuthFileHandle.close()
        authExists = False
    except Exception as e:
        print('Exception: ', e)
        LogData(AuthFileName+' error while closing')


#######################
def CloseVNCStream():
    #closes the vncserver-x11.log file stream
    global vncFileName
    global VNCPos
    global vncFileHandle
    global vncExists

    try:
        LogData('closing '+vncFileName)
        vncFileHandle.close()
        vncExists = False
    except Exception as e:
        print('Exception: ', e)
        LogData(vncFileName+' error while closing')


#######################
def CheckAuthLog():
    #checks if auth.log updated, if so read in and check for new login failures
    global AuthFileName
    global AuthPos
    global AuthFileHandle
    NewBlocks = False
    BlockStatus = False
    #AuthPos = 0

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
            NewBlocks = ScanAndCompare(line, 'auth.log')
            if NewBlocks: BlockStatus = True
        # Update the initial size to the current size
        AuthPos = alogsize
    
    # don't do this anymore, superceded by checking inode
    #elif alogsize < AuthPos: #log was rotated
    #    LogData('auth.log rotated')
    #    AuthPos = 0
    #    AuthFileHandle.close()
    #    OpenAuthAsStream()
    return BlockStatus


#######################
def CheckVNCLog():
    #checks if vncserver-x11.log updated, if so read in and check for new login failures
    global vncFileName
    global vncFileHandle
    global VNCPos
    global vncExists
    NewBlocks = False
    BlockStatus = False
    #VNCPos = 0

    vnclogsize = os.stat(vncFileName).st_size
    if vnclogsize > VNCPos:
        # Move the file pointer to the previous position
        vncFileHandle.seek(VNCPos)
        # Read the new lines added to the file
        new_data = vncFileHandle.read()
        
        # Process the new lines
        lines = new_data.split('\n')
        for line in lines:
            NewBlocks = ScanAndCompare(line, 'vncserver-x11.log')
            if NewBlocks: BlockStatus = True
                
        # Update the initial size to the current size
        VNCPos = vnclogsize
    #elif vnclogsize < VNCPos: #log was rotated
    #    LogData('vncserver-x11.log rotated')
    #    VNCPos = 0
    #    vncFileHandle.close()
    #    OpenVNCAsStream()
    return BlockStatus


#######################
def SaveSettings():
    #save last settings to settings.ini
    global localip
    global BlockFileName
    global AuthFileName
    global failcount
    global iniFileName
    global restart_time
    global aAutoBlockUsers
    global sAutoBlockUsers

    #if not inifile exists, create it
    if not os.path.isfile(iniFileName):
        LogData('saving settings')
        # Create a new configparser object
        config = configparser.ConfigParser()
        # Set some example settings
        config['Settings'] = {
            'localip': localip,
            'blockfile': BlockFileName,
            'authfile': AuthFileName,
            'failcount': failcount,
            'vncfile': vncFileName,
            'restart_time': restart_time,
            'autoblockusers': sAutoBlockUsers
        }
        # Save the settings to an INI file
        try:
            with open(iniFileName, 'w') as configfile:
                config.write(configfile)
            configfile.close()
        except Exception as e:
            print('Exception: ', e)
            LogData('error saving settings.ini')


#######################
def CheckLocalIP(CheckString):
    #is this ip in the local ip list?
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
def CheckAutoBlockUsers(username):
    #check if user is in the auto block list
    global aAutoBlockUsers
    ret = False
    username = username.strip()
    username = username.upper()
    if username == '':
        return ret
    if debugmode: print('checking user: '+username)
    for i in range(len(aAutoBlockUsers)):
        if aAutoBlockUsers[i] == username:
            ret = True
            if debugmode: print('bad user: '+username)
            #LogData('Autoblock bad user: '+aAutoBlockUsers[i]) #spams logfile, now incl. in IP block reason
            return ret
    return ret


#######################
def SplitAutoBlockUsers(userList):
    #split comma separated list of users into an array
    global aAutoBlockUsers
    #aAutoBlockUsers = userList.split(',')
    userList = userList.upper()
    LogData('autoblock users: '+str(userList))
    aAutoBlockUsers = [x.strip() for x in userList.split(',')]
    


#######################
def LoadSettings():
    # Load the settings from the INI file at startup, this will override the defaults, but not user set vars
    global localip
    global BlockFileName
    global AuthFileName
    global failcount
    global vncFileName
    global iniFileName
    global authExists
    global vncExists
    global restart_time
    global debugmode
    global sAutoBlockUsers

    LogData('loading settings')
    rt = False

    #set some defaults, ini will override
    localip = '192.168.'
    failcount = 2
    restart_time = 'None' #'00:10:10'
    rt = True
    if not debugmode:
        BlockFileName = StartDir+slash+'blocklist.dat'
        AuthFileName = '/var/log/auth.log'
        vncFileName = '/var/log/vncserver-x11.log'
    else:
        BlockFileName = StartDir+slash+'blocklist.dat'
        AuthFileName = StartDir+slash+'auth.log'
        vncFileName = StartDir+slash+'vncserver-x11.log'
        #sAutoBlockUsers = 'root,pi'
        #SplitAutoBlockUsers(sAutoBlockUsers)

    if os.path.isfile(iniFileName):
        LogData('reading settings.ini')
        config = configparser.ConfigParser()
        try:
            config.read(iniFileName)
            # Access the settings
            localip = config.get('Settings','localip', fallback='192.168.')
            if not debugmode: BlockFileName = config.get('Settings', 'blockfile', fallback = StartDir+slash+'blocklist.dat')
            if not debugmode: AuthFileName = config.get('Settings', 'authfile', fallback = '/var/log/auth.log')
            fc = config.get('Settings','failcount', fallback= '2')
            restart_time = config.get('Settings','restart_time', fallback= 'None')
            try:
                failcount = int(fc)
            except ValueError:
                LogData('error: failcount is not an integer, using default of 2: received-->'+fc)
                failcount = 2
            if not debugmode: vncFileName = config.get('Settings','vncfile', fallback= StartDir+slash+'vncserver-x11.log')
            sAutoBlockUsers = config.get('Settings','autoblockusers', fallback= '')
            # show me the settings
            LogData("loaded settings.ini:")

            rt = True
        except:
            LogData('error loading settings.ini')
            rt = False
        SplitAutoBlockUsers(sAutoBlockUsers)
    #else:
    #    LogData('settings.ini not found, using defaults:')
    #    localip = '192.168.'
    #    BlockFileName = StartDir+slash+'blocklist.dat'
    #    AuthFileName = '/var/log/auth.log'
    #    failcount = 2
    #    vncFileName = '/var/log/vncserver-x11.txt'
    #    restart_time = '00:10:10'
    #    rt = True

    authExists = True if (os.path.isfile(AuthFileName)) else False
    vncExists = True if (os.path.isfile(vncFileName)) else False

    LogData(f"localip(ini): {localip}")
    SplitLocalIP(localip)
    LogData(f"blockfile: {BlockFileName}")
    if authExists: LogData(f"authfile: {AuthFileName}")
    if vncExists: LogData(f"vncfile: {vncFileName}")
    LogData(f"failcount: {failcount}")
    LogData(f"restart_time: {restart_time}")


    return rt


#######################
def OpenLogFile():
    global LogFileName
    global logFileHandle
    global slash
    global Logging
    
    if not Logging:
        print('-- logging to file is off --')
        return

    if not os.path.isdir(StartDir + slash + 'logs'):
        try:
            os.mkdir(StartDir + slash + 'logs')
        except OSError as e:
            if e.errno != errno.EEXIST:
                Logging = False
                CloseGracefully(exitcode = 15)
            else:
                print('log directory already exists, but should not be here as OS said it wasn''t here')

    LogFileName = StartDir + slash + 'logs' + slash + 'authlogger.log'
    try:
        logFileHandle = open(LogFileName, 'a')
    except:
        print('error opening logfile')
        ErrorArg(5)
    LogData('authlogger started. Version: '+version)


#######################
def LogData(sdata):
    #write timestamp+sdata to logfile
    global logFileHandle
    global Logging
    global newlogdata
    
    print('['+TimeStamp()+']:'+sdata)
    if Logging: 
        CheckLogSize()
        logFileHandle.write('['+TimeStamp()+']:'+sdata + '\n')
        newlogdata = True


#######################
def TimeStamp():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))


#######################
def CloseLogFile():
    global logFileHandle
    global Logging
    
    if not Logging: return
    LogData('authlogger stopped.\n')
    FlushLogFile()
    logFileHandle.close()


#######################
def FlushLogFile():
    global logFileHandle
    global Logging
    global newlogdata
    
    if not Logging: return
    logFileHandle.flush()
    newlogdata = False


#######################
def orr(a, b):
    return bool(a) or bool(b)


#######################
def get_file_inode(file_path):
    #get inode and modification time of file
    try:
        stat_info = os.stat(file_path)
        return stat_info.st_ino
    except FileNotFoundError:
        return None, None


#######################
def is_log_rotated( original_inode, file_path ):
    #check if log file has been rotated
    current_inode = get_file_inode(file_path)
    
    if current_inode is None:
        LogData("File not found while checking inode: "+file_path)
        return False
    
    if original_inode != current_inode:
        LogData("Log file rotated (inode change: "+file_path+"): "+str(original_inode)+":"+str(current_inode))
        time.sleep(1.5) #wait to prevent double seeing the inode change.
        return True
    return False


#######################
def ReOpenLogFilesAsStream(which):
    #close and reopen the log files as streams
    match which:
        case 'auth':
            CloseAuthStream()
            OpenAuthAsStream()
        case 'vnc':
            CloseVNCStream()
            OpenVNCAsStream()
        case _:
            LogData('error: ReOpenLogFilesAsStream(), unknown which: '+which)


#######################
def CheckLogSize():
    #check if log file is too big, if so, rename it and start a new one
    global LogFileName
    global logFileHandle
    global Logging
    
    if not Logging: return
    if os.path.isfile(LogFileName):
        if os.stat(LogFileName).st_size > (1024 * 1024 * 10): #10MB
            print('Cycling logfile')
            FlushLogFile()
            logFileHandle.close()
            try:
                if os.path.isfile(LogFileName+'.old'):
                    if os.path.isfile(LogFileName+'.old.1'):
                        os.remove(LogFileName+'.old.1')
                    os.rename(LogFileName+'.old', LogFileName+'.old.1')
                os.rename(LogFileName, LogFileName+'.old')
            except OSError as e:
                print('error renaming logfile')
                ErrorArg(6)
            OpenLogFile()


########################################################
####################### [ MAIN ] #######################
########################################################
def main():
    
    ClearScreen()
    global Logging
    global StartDir
    global debugmode
    global slash
    global authExists
    global vncExists
    global sAutoBlockUsers
    global LastCheckIn
    global AuthFileName
    global vncFileName
    global VNCPos
    global AuthPos
    global AuthLogInode
    global VNCLogInode
    global newlogdata

    newlogdata = False
    AuthPos = 0
    VNCPos = 0
    flushcount = 80
    LastCheckIn = ""
    sAutoBlockUsers = ''
    iFlush = 0 #flush log data every 10 seconds (approx)
    runwhich = 4 #every 4th (0.25*4=1 sec) time, check for new blocks
    runnow = 0 #current run count
    authBlocks = False
    vncBlocks = False
    BlockStatus = False #if new blocks added, set to True, so it can save the blocklist file
    AuthLogInode = None
    VNCLogInode = None
    slash = '/'
    Logging = True

    signal.signal(signal.SIGINT, CloseGracefully) #ctrl-c detection
    signal.signal(signal.SIGTERM, CloseGracefully) #shutdown detection
    
    CheckIsLinux()
        
    StartDir = os.getcwd().removesuffix(slash)
    OpenLogFile()
    Welcome()
    GetArgs()
    if debugmode:
        print("A+") if (os.path.isfile(AuthFileName)) else print("A-")
        print("V+") if (os.path.isfile(vncFileName)) else print("V-")
        flushcount = 10

    time.sleep(3)
    ClearIPTables()
    OpenBlockList()
    PrintBlockList()
    #OpenLogFilesAsStream()

    LogData('opening logfiles as stream')

    if not orr(authExists, vncExists): CloseGracefully(10) #if neither file exists, exit, why else are we running?
    if authExists: OpenAuthAsStream()
    if vncExists: OpenVNCAsStream()
   
    while True:
        iFlush += 1
        if iFlush > flushcount: #flush log every 20 (0.25*80) seconds, not immediately as slows things down
            iFlush = 0
            FlushLogFile()
            if BlockStatus: 
                if debugmode: print('New blocks added to blocklist file')
                SaveBlockList()
                BlockStatus = False
        CheckRestartTime() #if current time is equal to restart_time, exit the script (bash will restart it)
        runnow += 1
        if runnow >= runwhich:
            runnow = 0
            AmAlive()
            
            if is_log_rotated(AuthLogInode, AuthFileName): ReOpenLogFilesAsStream('auth')
            
            if is_log_rotated(VNCLogInode, vncFileName): ReOpenLogFilesAsStream('vnc')

            if authExists: authBlocks = CheckAuthLog()
            if vncExists: vncBlocks = CheckVNCLog()
            if authBlocks or vncBlocks: BlockStatus = True
            if not (authExists and vncExists): CloseGracefully(10) #because a log cycle could cause one to not exist

        time.sleep(0.25) #only cycle 4hz
    #<--while True:


    #should never reach here due to ctrl-c detection
    CloseGracefully()
    ErrorArg(11) #certainly not 'ere
    sys.exit(255) #just in case...

if __name__ == '__main__':
    main()   
