#*todo
# on ctrl-c, save iptables gets duplicated. error might be in try/except/finally block.
#
# keyboard only works locally. disabled for now. find SSH (and) RPi compatible workaround.
#
#*notes
# literally too lazy to do anything else to this unless it breaks.
# currently in use on my rpi because it's always connected and powered on.
# at various points I've tried to implement keyboard input, but over shh (even with sshkeyboard)
# it breaks.
#
#'iptables -I INPUT -s '+slBlocklist.Strings[i]+' -j DROP'
#
# change notes
# 2023-06-01 beginning to implement failcount, but not done yet
#

#from getpass import getpass #not used anymore, should be run as sudo root, not try to elevate
import os, argparse, sys, io, time, subprocess
from libby import *
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

version = "2023-06-11r4" #really need to update this every time I change something
#2023-02-12 21:37:26

# Initialize ncurses
#stdscr = curses.initscr()
#curses.noecho()
#curses.cbreak()
#stdscr.keypad(True)    
# Set nodelay mode to enable non-blocking input
#stdscr.nodelay(True)

class cBlock:
    def __init__(self, vdatetime=None, ip=None): #failcount not needed as count of datetime array will show failures
        self.vdatetime = []
        self.ip = ip

    def add_datetime(self, vdatetime):
        self.vdatetime.append(vdatetime)


aBlocklist = [] #array of cBlock objects


# Redefine the print function to include carriage return (for curses)
#def print(*args, **kwargs):
#    stdscr.addstr(*args, **kwargs)
#    stdscr.refresh()


# Check if there is any input available
#def is_key_pressed():
#    # Check for keyboard input
#    key = stdscr.getch()
#    # Process the key if it has a value
#    if key != curses.ERR:
#        return chr(key)
#    else:
#        return None
#        # Handle other keypresses
#        #print(f"You pressed: {chr(key)}")

def welcome():
    print('\n[==-- Wheel reinvention society presents: authlogger! --==]\n')
    print('Does some of what other, better, programs do, but worse!\n')
    print('Seriously, if you want to block IPs, use fail2ban, it\'s much better, but this is simpler...\n')
    print('version: '+version)
    print("Press ESCAPE to exit, or just crash out with ctrl-c, whatever")
    

def getArgs():
    print("getting args")
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
    parser.add_argument('-b', '--blockfile', action='store', help='blocklist file, incl. path', default=StartDir+'/blocklist.txt')
    parser.add_argument('-f', '--failcount', action='store', type=int, help='number of login failures to block IP (defaults to 2)', default=1)
    parser.add_argument('-i', '--inifile', action='store', help='.ini file and path', default='')
    parser.add_argument('-l', '--localip', action='store', help='local IP range to ignore (default 192.168.)', default='192.168.')
    #parser.add_argument('-p', '--PassThru', dest='PassThru', action='store', help='parameters to pass to CMD', default='')
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
        #blockfile = StartDir+slash+"blockie.txt"
    if authfile == '': ErrorArg(2)
    if blockfile == '': ErrorArg(2)
    if failcount < 1: ErrorArg(2)
    if localip == '': ErrorArg(2)
    if not os.path.isfile(authfile): ErrorArg(0)

    blockcount = FileLineCount(blockfile) #change this, no longer just a line per ip
    authlinecount = FileLineCount(authfile)
    print('localip>'+localip)
    print('auth>'+authfile+' and contains: '+str(authlinecount)+' lines')
    print('block>'+blockfile+' and contains: '+str(blockcount)+' lines')
    print('ini>'+args.inifile)


def CloseGracefully(signal=None, frame=None):
    print('closing...')
    #if ctrl-c is pressed, save iptables and exit
    global aBlocklist
    global AuthFileHandle
    AuthFileHandle.close()
    SaveBlockList()
    SaveSettings()
    if not debugmode:
        print('closing...')
        subprocess.call(['/sbin/iptables-save'])

#    curses.nocbreak()
#    stdscr.keypad(False)
    #curses.echo()
#    curses.endwin()
    ErrorArg(0)


def BlockIP(ip):
    if not debugmode:
        print('pushing ->'+ip)
        subprocess.call(['/sbin/iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'])
        #subprocess.call(['/sbin/iptables-save']) #has to save because no clean exit, update, now done in CloseGracefully()
    else:
        print("ADD/debug mode: iptables -I INPUT -s "+ip+" -j DROP")

def FirstRunCheckBlocklist():
    #if first run, check aBlocklist for failures and add them to iptables
    global aBlocklist
    global failcount
    print('checking blocklist/first run: '+str(len(aBlocklist))+ ' entries')
    for x in range(0, len(aBlocklist)):
        #print(aBlocklist[x].ip+' '+str(len(aBlocklist[x].datetime)))
        if len(aBlocklist[x].datetime) >= failcount:
            BlockIP(aBlocklist[x].ip)
            #print('blocking: "'+aBlocklist[x].ip+'"')


def AddNewIPToBlocklist(ip, timeblocked):
    global aBlocklist
    #update iptables rules without clearing them all first
    print('adding: '+ip)
    aBlocklist.append(cBlock(ip=ip))
    aBlocklist[len(aBlocklist)-1].add_datetime(timeblocked)


def CheckBlocklist(ip, timeblocked):
    #print('checking: '+ip)
    #check to see if ip is already in blocklist
    global aBlocklist
    foundit = False
    for x in range(0, len(aBlocklist)):
        if aBlocklist[x].ip == ip:
            for y in range(0, len(aBlocklist[x].datetime)):
                if aBlocklist[x].datetime[y] == timeblocked:
                    foundit = True
                    break

                    #aBlocklist[x].datetime.append(timeblocked)
                    #foundit = True
                    #if len(aBlocklist[x].datetime) >= failcount: #check to see if this exceeds the failcount
                    #    BlockIP(ip)
                    #break
    if not foundit:
        AddNewIPToBlocklist(ip, timeblocked)
        if failcount == 1: #if failcount is 1, block on first failure
            BlockIP(ip)


def GetDateTime(authstring):
    #get the date and time from the auth.log string, convert to YYYYMMDDHHMMSS
    timey = time.strftime('%Y', time.localtime(time.time()))
    timey = time.strftime('%Y%m%d%H%M%S', time.strptime(timey+" "+authstring[:15], "%Y %b %d %H:%M:%S"))
    return timey



def scanandcompare(aline):
    global authstrings
    global blocklist
    global localip
    global failcount

    newblock = False
    
    if (((aline.find('Failed password for',) >= 0) or (aline.find('Did not receive identification') >= 0)) and (aline.find(localip) < 0)):
        tmp = aline.split(' ')
        if aline.find('Failed') >= 0:
            checkline = tmp[len(tmp)-4]
        else:
            checkline = tmp[len(tmp)-3]

        #print("checkline: " + checkline)
        #print("aline: " + str(aline))
        #print("datetime: " + GetDateTime(aline))


        CheckBlocklist(checkline, GetDateTime(aline))
#            foundit = isIPinBlocklist(aline)
#            if not foundit:            
#                print('adding: '+aline)
#                blocklist.append(aline)
#                newblock = True
#                AddNewIPToBlocklist(aline)

    return newblock



#def key_capture_thread():
#    global keep_going
#    input()
#    keep_going = False

def press(key):
    print(f"'{key}' pressed")
#    if key == "escape":
#        stop_listening()
#        ErrorArg(0)


def authModified():
    global authlogModtime
    global authfile

    authModified = False

    if (os.path.isfile(authfile)):
        if (os.path.getmtime(authfile) != authlogModtime):
            authlogModtime = os.path.getmtime(authfile)
            authModified = True
    else:
        print('auth.log file not found')
        ErrorArg(2)

    return authModified


def OpenBlockList():
    print('opening blocklist')
    #read in the blocklist file to aBlocklist array
    global aBlocklist
    global blockfile

    #aBlocklist = [] #should be the first time this is called. / wasn't though was it

    if (os.path.isfile(blockfile)):
        try:
            with open(blockfile, 'rb') as fblockfile:
                aBlocklist = pickle.load(fblockfile)
            fblockfile.close()
            FirstRunCheckBlocklist()
        except:
            print('blocklist file is corrupt, will be overwritten on save')

    else:
        print('blocklist file not found, will be created on save')
        


def SaveBlockList():
    #print('saving blocklist (dump)')
    #save the blocklist array to the blocklist file
    global blocklist
    global blockfile
    #for x in range(0, len(aBlocklist)):
    #    for y in range(0, len(aBlocklist[x].datetime)):
    #        print(aBlocklist[x].ip+' '+aBlocklist[x].datetime[y])
    #print("---")
    print('saving blocklist')
    with open(blockfile, "wb") as fblockfile:
        pickle.dump(aBlocklist, fblockfile)
    fblockfile.close()


#def GetKey():
    #what key is it
#    key = readchar.readchar()
#    if key == '\x1b':
#        print("Escape key was pressed.")
#        CloseGracefully()


def OpenAuthLogAsStream():
    print('opening auth.log as stream')
    global authfile
    global AuthPos
    global AuthFileHandle
    alogsize = os.stat(authfile).st_size
    # Check if the file size has changed
    with open(authfile, 'r') as AuthFileHandle: #gets closed in CloseGracefully()
        while True:
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
        print('error saving settings.ini')
            

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
            failcount = config['Settings']['failcount']

            # show me the settings
            print("loaded settings.ini:")
            print(f"localip: {localip}")
            print(f"blockfile: {blockfile}")
            print(f"authfile: {authfile}")
            print(f"failcount: {failcount}")
            rt = True
        except:
            print('error loading settings.ini')
            rt = False
    else:
        print('settings.ini not found, using defaults')
        rt = False
    return rt


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
    AuthPos = 0
    global slash
    slash = '/'
    signal.signal(signal.SIGINT, CloseGracefully) #ctrl-c detection


    if not checkOSisLinux():
        print("not linux, so going into debug mode")
        slash = '\\'
        debugmode = True
        
    rebuild = False
    StartDir = os.getcwd().removesuffix(slash)

    welcome()
    getArgs()
    try:
        OpenBlockList()
        OpenAuthLogAsStream()

    except:
        print('error in main()')
    finally:
        CloseGracefully()
        




    ErrorArg(0)
    #should never reach here
    sys.exit(255)

if __name__ == '__main__':
    main()   



        

#def OpenAuthLogAsStream()
    #open the auth.log file as a stream
    #with the stream open, get a handle to it and read in data from it, on \n process received string from stream
#import os
#import time

#    filename = 'auth.log'

#    # Get the initial size of the file
#    initial_size = os.stat(filename).st_size

#    while True:
#        # Check if the file size has changed
#        if os.stat(filename).st_size > initial_size:
#            with open(filename, 'r') as file:
#                # Move the file pointer to the previous position
#                file.seek(initial_size)
#                # Read the new lines added to the file
#                new_data = file.read()
#                
#                # Process the new lines
#                lines = new_data.split('\n')
#                for line in lines:
#                    if 'error' in line:
#                        # Perform your desired actions here
#                        print("Found 'error' in line:", line)
#                        
#                # Update the initial size to the current size
#                initial_size = os.stat(filename).st_size
#        
#        # Sleep for a short interval before checking again
#        time.sleep(1)
