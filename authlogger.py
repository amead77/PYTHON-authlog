# Notes:
# Requires Python >= 3.10 due to match case.
#
# This is a simple script to monitor the auth.log file for failed login attempts and block the IP address
# if the number of failed attempts is >= failcount.
#
# currently in use on my rpi because it's always connected and powered on.
# at various points I've tried to implement keyboard input, but over shh (even with sshkeyboard)
# it breaks. curses can suck my dick as that solves one problem by introducing another.
#
# the actual firewall rule setting is: 'iptables -I INPUT -s <IP> -j DROP'
#
# TODO:
#   BUG: ini file is loaded and unloaded to settings.ini without user intervention and ignores the -i arg.
#        this is because I was testing configparser and forgot about it until just now (2023-06-27)
#   FIXME: keyboard only works locally. disabled for now. find SSH (and) RPi compatible workaround.
#
# change notes
# 2023-06-01 beginning to implement failcount, but not done yet
# 2023-06-18 pretty much done, tidying up in progress. wasn't much in libby.py so i merged it back in/
# 2023-06-25 added logging to see what is happening. suspect not correctly blocking new IPs, will see
# 2023-06-27 added comments, changed some wording.
#
#
#
# How this works:
# Reads /var/log/auth.log file, parses it very simply, creates a array of IP addresses along with the datetime
# that they failed login.
# If the number of datetime entries is >= failcount, then send to IPTables to add to firewall rules.
#
#
# in simple terms the main order of code is:
# Create cBlock class, used as a record/struct
# create aBlocklist[] which becomes and array of cBlock class
# create aActiveBlocklist[] which is an array of IP addresses that are actually blocked.
# main() which is at the bottom
#   clear_screen()
#   set ctrl-c detection
#   set global variables and check if running on linux, if not go into debug mode (doesn't actually send to iptables in debug mode)
#   OpenLogFile() to initialise the log file for sending data to (also prints to screen on logging)
#   welcome() to show welcome text, duh..
#   getArgs() to get command line arguments, override ini settings if ini specified on cmd line plus other arguments
#   ClearIPTables() to clear out IPTables rules before setting any new ones
#   OpenBlocklist() to load the blocklist file into memory
#     FirstRunCheckBlocklist() to block any IPs already in the blocklist file if the number of datetime entries is >= failcount
#   PrintBlockList() to print the current blocklist to screen and log file
#   OpenAuthLogAsStream() to open the auth.log file as a stream, once opened stay in this function until ctrl-c
#      #Every time authlog gets new data, split it into lines and process each line by sending to scanandcompare()
#      #scanandcompare() checks if the line is a failed login attempt, if it is, it sends the IP to CheckBlocklist()
#    CheckBlocklist() checks if the IP is already in the blocklist aBlocklist[], if yes and unique, it adds the datetime to the cBlock object, else
#      #if the IP is not in the blocklist, it adds the IP to the aBlocklist[].
#      #if the number of datetime entries in the cBlock object of aBlocklist[] is >= failcount, it sends the IP to BlockIP()
#      BlockIP() sends the IP to iptables to be blocked, and adds the IP to aActiveBlocklist[] to keep track of what is currently blocked
#      #if Ctrl-C is detected, jump to: CloseGracefully()
# CloseGracefully() to close the auth.log stream and save the blocklist to file


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

version = "2023-06-27r0" #really need to update this every time I change something
#2023-02-12 21:37:26

# Initialize ncurses
#stdscr = curses.initscr()
#curses.noecho()
#curses.cbreak()
#stdscr.keypad(True)    
# Set nodelay mode to enable non-blocking input
#stdscr.nodelay(True)

class cBlock:
    def __init__(self, vdatetime=None, ip=None, reason = None): #failcount not needed as count of datetime array will show failures
        self.vdatetime = []
        self.ip = ip
        self.reason = []

    def add_datetime(self, vdatetime):
        self.vdatetime.append(vdatetime)

    def add_reason(self, reason):
        self.reason.append(reason)

aBlocklist = [] #array of cBlock objects
aActiveBlocklist = [] #array of ip addresses

##########################################################################################################################

#######################
def clear_screen():
    if os.name == 'nt':  # for Windows
        os.system('cls')
    else:  # for Unix/Linux/MacOS
        os.system('clear')


#######################
def ErrorArg(err):
    match err:
        case 0:
            print("bye!")
        case 1:
            print("no worries, bye!")
        case 2:
            HELP()
        case 3:
            print("**NEEDS TO RUN AS (SUDO) ROOT, or it cannot access auth.log and set iptables rules")
            HELP()
        case 4:
            print("got stuck in a loop")
        case 5:
            print("unable to create or write to logfile")
        case _:
            print("dunno, but bye!")
    sys.exit(err)


#######################
def checkOSisLinux():
    #this is because it is designed to run on Linux, but I also code on Windows, in which case I don't want it to run all the code
    if not sys.platform.startswith('linux'):
        debugmode = True
        return False
    else:
        return True


#######################
def HELP():
    print("**something went wrong. I don't know what, so if you started with no parameters it probably means a file didn't exist or you ran as a normie rather than root\n")
    print("auth.log file to scan            : -a, --authfile <filename>")
    print("blocklist file with IPs          : -b, --blockfile <filename>")
    print("number of attempts to block      : -f, --failcount <2>")
    print("inifile with settings (not req.) : -i, --inifile <filename>")
    print("local ip address range to ignore : -l, --localip <192.168.>")
    print("Remember: must run as sudo/root or it cannot block IPs\n")


#######################
def welcome():
    print('\n[==-- Wheel reinvention society presents: authlogger! --==]\n')
    print('Does some of what other, better, programs do, but worse!\n')
    print('Seriously, if you want to block IPs, use fail2ban, it\'s much better, but this is simpler...\n')
    print('version: '+version)
    print("To exit just crash out with ctrl-c, keyboard control over ssh is iffy.")
    

#######################
def getArgs():
    LogData("getting args")
    global blockfile
    global authfile
    global blockcount
    global localip
    global failcount
    global inifile
    global StartDir
    global slash
    #failure = False
    loadsettingsstatus = False
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--authfile', action='store', help='auth.log file incl. path', default='/var/log/auth.log')
    parser.add_argument('-b', '--blockfile', action='store', help='blocklist file, incl. path', default=StartDir+slash+'blocklist.txt')
    parser.add_argument('-f', '--failcount', action='store', type=int, help='number of login failures to block IP (defaults to 2)', default=1)
    parser.add_argument('-i', '--inifile', action='store', help='.ini file and path', default='')
    parser.add_argument('-l', '--localip', action='store', help='local IP range to ignore (default 192.168.)', default='192.168.')
    args = parser.parse_args()

    #load the ini file before anything else, so it can be overwritten by command line args
    inifile = args.inifile
    if inifile != '':
        loadsettingsstatus = LoadSettings()

    
    
    if (args.authfile != parser.get_default("authfile")) or (loadsettingsstatus == False):
        authfile = args.authfile

    if (args.blockfile != parser.get_default("blockfile")) or (loadsettingsstatus == False):
        blockfile = args.blockfile
    
    if (args.localip != parser.get_default("localip")) or (loadsettingsstatus == False):
        localip = args.localip

    if (args.failcount != parser.get_default("failcount")) or (loadsettingsstatus == False):
        failcount = args.failcount

    if debugmode:
        authfile = StartDir+slash+"auth.log"
    if authfile == '': ErrorArg(2)
    if blockfile == '': ErrorArg(2)
    if failcount < 1: ErrorArg(2)
    if localip == '': ErrorArg(2)
    if not os.path.isfile(authfile): ErrorArg(0)

    #blockcount = FileLineCount(blockfile) #change this, no longer just a line per ip
    #authlinecount = FileLineCount(authfile)
    LogData('localip>'+localip)
    LogData('auth>'+authfile)
    LogData('block>'+blockfile)
    LogData('ini>'+args.inifile)
    LogData('failcount>'+str(failcount))


#######################
def PrintBlockList():
    global aBlocklist
    LogData('printing blocklist')
    for i in range(len(aBlocklist)):
        LogData(aBlocklist[i].ip+':')
        for x in range(len(aBlocklist[i].vdatetime)):
            LogData('-->'+ReverseDateTime(aBlocklist[i].vdatetime[x]))


#######################
def CloseGracefully(signal=None, frame=None):
    LogData('closing...')
    #if ctrl-c is pressed, save iptables and exit
    global aBlocklist
    global AuthFileHandle
    #AuthFileHandle.close() #not requred, as with statement closes it automatically
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
        if len(aBlocklist[x].vdatetime) >= failcount:
            #print('len(aBlocklist[x].vdatetime) '+str(len(aBlocklist[x].vdatetime)))
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
            for y in range(0, len(aBlocklist[x].vdatetime)):
                if aBlocklist[x].vdatetime[y] == timeblocked:
                    foundit = True
                    break

    if not foundit:
        if dtfound >= 0:
            LogData('adding datetime: '+ip+' ['+reason+']')
            aBlocklist[dtfound].add_datetime(timeblocked)
            aBlocklist[dtfound].add_reason(reason)
            if len(aBlocklist[dtfound].vdatetime) >= failcount:
                BlockIP(ip)
        else:
            LogData('['+str(len(aBlocklist))+'] adding: '+ip+' ['+reason+']')
            aBlocklist.append(cBlock(ip=ip))
            aBlocklist[len(aBlocklist)-1].add_datetime(timeblocked)
            aBlocklist[len(aBlocklist)-1].add_reason(reason)
            if failcount == 1: #if failcount is 1, block on first failure
                BlockIP(ip)
        

#######################
def GetDateTime(authstring):
    #get the date and time from the auth.log string, convert to YYYYMMDDHHMMSS
    timey = time.strftime('%Y', time.localtime(time.time()))
    timey = time.strftime('%Y%m%d%H%M%S', time.strptime(timey+" "+authstring[:15], "%Y %b %d %H:%M:%S"))
    return timey


#######################
def ReverseDateTime(authstring):
    #get the date and time in the format YYYYMMDDHHMMSS and convert to YYYY-MM-DD HH:MM:SS
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
def scanandcompare(aline):
    global authstrings
    global blocklist
    global localip
    global failcount
    
    #newblock = False
    
    if (((aline.find('Failed password for',) >= 0) or (aline.find('Did not receive identification') >= 0)) and (aline.find(localip) < 0)):
        tmp = aline.split(' ')
        if aline.find('Failed') >= 0:
            checkline = tmp[len(tmp)-4]
        else:
            checkline = tmp[len(tmp)-3]

        CheckBlocklist(checkline, GetDateTime(aline), aline[16:])


#######################
def authModified():
    global authlogModtime
    global authfile

    authModified = False

    if (os.path.isfile(authfile)):
        if (os.path.getmtime(authfile) != authlogModtime):
            authlogModtime = os.path.getmtime(authfile)
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
    global blockfile

    #aBlocklist = [] #should be the first time this is called. / wasn't though was it

    if (os.path.isfile(blockfile)):
        try:
            with open(blockfile, 'rb') as fblockfile:
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
    global blockfile

    LogData('saving blocklist')
    with open(blockfile, "wb") as fblockfile:
        pickle.dump(aBlocklist, fblockfile)
    #fblockfile.close() not required with 'with'


#######################
def OpenAuthLogAsStream():
    LogData('opening auth.log as stream')
    global authfile
    global AuthPos
    global AuthFileHandle
    iFlush = 0
    alogsize = os.stat(authfile).st_size
    # Check if the file size has changed
    with open(authfile, 'r') as AuthFileHandle: #gets closed in CloseGracefully()
        while True:
            iFlush += 1
            if iFlush > 10: #flush log every 10 seconds, not immediately as slows things down
                iFlush = 0
                FlushLogFile()

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
                    scanandcompare(line)
                        
                # Update the initial size to the current size
                AuthPos = alogsize
            elif alogsize < AuthPos: #log was rotated
                AuthPos = 0
            time.sleep(1)


#######################
def SaveSettings():
    #save last settings to settings.ini
    global localip
    global blockfile
    global authfile
    global failcount
    # Create a new configparser object
    config = configparser.ConfigParser()
    # Set some example settings
    config['Settings'] = {
        'localip': localip,
        'blockfile': blockfile,
        'authfile': authfile,
        'failcount': failcount
    }
    # Save the settings to an INI file
    try:
        with open('settings.ini', 'w') as configfile:
            config.write(configfile)
        configfile.close()
    except:
        LogData('error saving settings.ini')
            

#######################
def LoadSettings():
    # Load the settings from the INI file at startup, this will override the defaults, but not user set vars
    global localip
    global blockfile
    global authfile
    global failcount
    rt = False
    config = configparser.ConfigParser()
    if  os.path.isfile('settings.ini'):
        try:
            config.read('settings.ini')
            # Access the settings
            localip = config['Settings']['localip']
            blockfile = config['Settings']['blockfile']
            authfile = config['Settings']['authfile']
            failcount = int(config['Settings']['failcount'])

            # show me the settings
            LogData("loaded settings.ini:")
            LogData(f"localip: {localip}")
            LogData(f"blockfile: {blockfile}")
            LogData(f"authfile: {authfile}")
            LogData(f"failcount: {failcount}")
            rt = True
        except:
            LogData('error loading settings.ini')
            rt = False
    else:
        LogData('settings.ini not found, using defaults')
        rt = False
    return rt


#######################
def OpenLogFile():
    global logfile
    global logFileHandle
    global slash
    if not os.path.isdir(StartDir + slash + 'logs'):
        os.mkdir(StartDir + slash + 'logs')
    logfile = StartDir + slash + 'logs' + slash + 'authlogger.log'
    try:
        logFileHandle = open(logfile, 'a')
    except:
        print('error opening logfile')
        ErrorArg(5)
    logFileHandle.write('authlogger started.\n')


#######################
def LogData(sdata):
    #write timestamp+sdata to logfile, then flush to disk
    global logFileHandle
    print(sdata)
    logFileHandle.write(TimeStamp()+'--'+sdata + '\n')
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


####################### [ MAIN ] #######################
def main():
    
    clear_screen()
    
    global localip
    global StartDir
    global blockcount
    global blockfile
    global authfile
    global debugmode
    global AuthPos
    global AuthFileHandle
    global logfile
    AuthPos = 0
    global slash
    slash = '/'
    signal.signal(signal.SIGINT, CloseGracefully) #ctrl-c detection


    if not checkOSisLinux():
        LogData("not linux, so going into debug mode")
        slash = '\\'
        debugmode = True
        
    rebuild = False
    StartDir = os.getcwd().removesuffix(slash)
    OpenLogFile()
    welcome()
    getArgs()
    time.sleep(3)
    ClearIPTables()
    #no longer use try...except...finally, as it was causing issues with ctrl-c, errors should be caught in the functions
    #try:
    OpenBlockList()
    PrintBlockList()
    OpenAuthLogAsStream()
    #except:
        #print('error in main()')
    #finally:

    #should never reach here due to ctrl-c detection
    CloseGracefully()
    ErrorArg(0)
    sys.exit(255)

if __name__ == '__main__':
    main()   
