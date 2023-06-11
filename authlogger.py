#*todo
#
# failure count is ignored. implement*****
# currently only blocks on first failure. need to implement a counter and block on x failures
# --create record array: ip, fail count
# --during scan increment fail count on every find
# --at end of scan block based on failcount
# --maybe also consider what is already in the blocklist
# --check timestamp in auth.log to see if it's been modified since last scan and to ignore existing IPs in blocklist from earlier in the auth.log
# keyboard only works locally. disabled for now. find SSH (and) RPi compatible workaround.
# inifile isn't actually used or even written to
# 
#
#*notes
# literally too lazy to do anything else to this unless it breaks.
# currently in use on my rpi because it's always connected and powered on.
# at various points I've tried to implement keyboard input, but over shh (even with sshkeyboard)
# it breaks.
# Should now try to raise auth level if not sudo root. that bit of code i stole off the net
# and can't remember where i got it from. If you recognise it and let me know, i'll link
# credit to it.
#
#
#'iptables -I INPUT -s '+slBlocklist.Strings[i]+' -j DROP'
#
# change notes
# 2023-06-01 beginning to implement failcount, but not done yet
#

from getpass import getpass
import os, argparse, sys, io, time, subprocess
from libby import *
import signal #for ctrl-c detection
import pickle #for saving blocklist
import datetime #for timestamping#

#from sshkeyboard import listen_keyboard, stop_listening

#import keyboard
#from subprocess import call

debugmode = True

version = "2023-06-11" #really need to update this every time I change something
#2023-02-12 21:37:26

authlogModtime = 0 #time of last auth.log modification


class cBlock:
    def __init__(self, datetime=None, ip=None): #failcount not needed as count of datetime array will show failures
        self.datetime = []
        self.ip = ip

    def add_datetime(self, datetime):
        self.datetime.append(datetime)


aBlocklist = [] #array of cBlock objects

signal.signal(signal.SIGINT, CloseGracefully) #ctrl-c detection
        


def welcome():
    print('\n[==-- Wheel reinvention society presents: authlogger! --==]\n')
    print('Does some of what other, better, programs do, but worse!\n')
    print('Seriously, if you want to block IPs, use fail2ban, it\'s much better, but this is simpler...\n')
    print('version: '+version)
    print("Press ESCAPE to exit, or just crash out with ctrl-c, whatever")
    

def getArgs():
    global blockfile
    global authfile
    global blockcount
    global localip
    global failcount
    global inifile

    #failure = False
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--authfile', action='store', help='auth.log file incl. path', default='/var/log/auth.log')
    parser.add_argument('-b', '--blockfile', action='store', help='blocklist file, incl. path', default=StartDir+'/blocklist.txt')
    parser.add_argument('-f', '--failcount', action='store', type=int, help='number of login failures to block IP (defaults to 1-currently ignored)', default=2)
    parser.add_argument('-i', '--inifile', action='store', help='.ini file and path', default='')
    parser.add_argument('-l', '--localip', action='store', help='local IP range to ignore (default 192.168.)', default='192.168.')
    #parser.add_argument('-p', '--PassThru', dest='PassThru', action='store', help='parameters to pass to CMD', default='')
    args = parser.parse_args()

#inifile isn't used yet
#failcount is ignored, currently always aBlocklist on first failure
    blockfile = args.blockfile
    localip = args.localip
    authfile = args.authfile
    failcount = args.failcount
    inifile = args.inifile
    if debugmode:
        authfile = StartDir+'\\auth.log'
        blockfile = StartDir+'\\blockie.txt'
    if authfile == '': ErrorArg(2)
    if blockfile == '': ErrorArg(2)
    if failcount < 1: ErrorArg(2)
    if localip == '': ErrorArg(2)

    blockcount = FileLineCount(blockfile) #change this, no longer just a line per ip

    print('localip>'+localip)
    print('auth>'+authfile)
    print('block>'+blockfile+' and contains: '+str(blockcount)+' lines')
    print('ini>'+args.inifile)
    




def CloseGracefully(signal, frame):
    #if ctrl-c is pressed, close iptables and exit
    if not debugmode:
        print('closing...')
        subprocess.call(['/sbin/iptables-save'])
    ErrorArg(0)


def BlockIP(ip):
    if not debugmode:
        print('pushing ->'+ip)
        subprocess.call(['/sbin/iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'])
        #subprocess.call(['/sbin/iptables-save']) #has to save because no clean exit, update, now done in CloseGracefully()
    else:
        print("ADD/debug mode: iptables -I INPUT -s "+ip+" -j DROP")


def AddNewIPToBlocklist(ip, timeblocked):
    global aBlocklist
    #update iptables rules without clearing them all first
    print('adding: '+ip)
    aBlocklist.append(cBlock(ip=ip))
    aBlocklist[len(aBlocklist)-1].add_datetime(timeblocked)
    if failcount == 1: #if failcount is 1, block on first failure
        BlockIP(ip)


def CheckBlocklist(ip, timeblocked):
    #check to see if ip is already in blocklist
    global aBlocklist
    foundit = False
    for x in range(0, len(aBlocklist)):
        if aBlocklist[x].ip == ip:
            for y in range(0, len(aBlocklist[x].datetime)):
                if aBlocklist[x].datetime[y] != timeblocked:
                    aBlocklist[x].datetime.append(timeblocked)
                    foundit = True
                    if len(aBlocklist[x].datetime) >= failcount: #check to see if this exceeds the failcount
                        BlockIP(ip)
                    break
    if not foundit:
        AddNewIPToBlocklist(ip, timeblocked)


def GetDateTime(authstring):
#    print("authlogModtime: " + str(authlogModtime))
    #format authlogModtime as yyyy-mm-dd hh:mm:ss
#    timey = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(authlogModtime))
#    print("authlogModtime: " + str(timey))
    #format authlogModtime as yyyymmddhhmmss but with leading zeros
#    timey = str(time.strftime('%Y%m%d%H%M%S', time.localtime(authlogModtime)))
#    print("authlogModtime: " + timey)
    #print time now as yyyy-mm-dd hh:mm:ss
#    print("time now: " + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
    #assuming year is current year, convert: Jun  4 18:03:55 to yyyy-mm-dd hh:mm:ss
    timey = time.strftime('%Y', time.localtime(time.time()))
    
    timey = time.strftime('%Y-%m-%d %H:%M:%S', time.strptime(timey+" "+authstring, "%Y %b %d %H:%M:%S"))
    return timey
#    print("timey: " + timey)



def scanandcompare():
    global authstrings
    global blocklist
    global localip
    global failcount

    newblock = False
    
    for x in range(0, len(authstrings)):
        aline = authstrings[x]
        if (((aline.find('Failed password for',) >= 0) or (aline.find('Did not receive identification') >= 0)) and (aline.find(localip) < 0)):
            tmp = aline.split(' ')
            if aline.find('Failed') >= 0:
                aline = tmp[len(tmp)-4]
            else:
                aline = tmp[len(tmp)-3]
            foundit = isIPinBlocklist(aline)
            if not foundit:            
                print('adding: '+aline)
                blocklist.append(aline)
                newblock = True
                AddNewIPToBlocklist(aline)

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



def main():
    global localip
    global StartDir
    global blockcount
    global blockfile
    global authfile

    global fblockfile
    global authstrings
    global inifile

    if not checkOSisLinux():
        print("not linux, so going into debug mode")
        debugmode = True
        
    rebuild = False
    StartDir = os.getcwd().removesuffix('/')

    welcome()
    getArgs()
 





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
