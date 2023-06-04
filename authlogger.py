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
#from sshkeyboard import listen_keyboard, stop_listening

#import keyboard
#from subprocess import call

debugmode = True

version = "2023-06-01" #really need to update this every time I change something
#2023-02-12 21:37:26

authlogModtime = 0 #time of last auth.log modification
blocklistModtime = 0 #time of last blocklist modification

class Block:
    def __init__(self, datetime, ip, failcount):
        self.datetime = datetime
        self.ip = ip
        self.failcount = failcount


        

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
        case _:
            print("dunno, but bye!")

    os.chdir(StartDir)
    sys.exit(err)




def welcome():
    #if debugmode:
    #    print("EUID: ", os.geteuid())
    #    dtime(2000)
    print('\n[==-- Wheel reinvention society presents: authlogger! --==]\n')
    print('Does some of what other, better, programs do, but worse!\n')
    print('Seriously, if you want to block IPs, use fail2ban, it\'s much better, but this is simpler...\n')
    print('version: '+version)
    print("Press ESCAPE to exit, or just crash out with ctrl-c, whatever")
    
    #don't bother to check for sudo/root for now.
    #if not is_root(): 
    #    if not debugmode: 
    #        #ErrorArg(3)
    #        prompt_sudo()


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
#failcount is ignored, currently always blocks on first failure
    blockfile = args.blockfile
    localip = args.localip
    authfile = args.authfile
    failcount = args.failcount
    inifile = args.inifile
    if debugmode:
        authfile = StartDir+'\\auth.log'
        blockfile = StartDir+'\\blocklist.txt'
    if authfile == '': ErrorArg(2)
    if blockfile == '': ErrorArg(2)
    if failcount < 1: ErrorArg(2)
    if localip == '': ErrorArg(2)

    blockcount = FileLineCount(blockfile)

    print('localip>'+localip)
    print('auth>'+authfile)
    print('block>'+blockfile+' and contains: '+str(blockcount)+' lines')
    print('ini>'+args.inifile)
    

def openblockfile():
    global blockfile
    global blocklist
    global fblockfile
    global authlogModtime
    if (os.path.isfile(blockfile)):
        authlogModtime = os.path.getmtime(authfile)
        fblockfile = io.open(blockfile, 'rt', buffering=1, encoding='utf-8', errors='ignore', newline='\n')
        blocklist=fblockfile.readlines()
        for x in range(0, len(blocklist)):
            blocklist[x]=blocklist[x].strip('\n')
        #print(blocklist)
        fblockfile.close()


def openauthfile():
    global authfile
    global blocklist
    global authstrings
    fauthfile = None
    #print('auth open')
    if (os.path.isfile(authfile)):
        try:
            print('attempt auth open: ' + authfile)
            fauthfile = io.open(authfile, 'rt', buffering=1, encoding='utf-8', errors='ignore', newline='\n')
            authstrings=fauthfile.readlines()
        except:
            pass
        finally:
            if fauthfile is not None:
                fauthfile.close
                print('auth close: ' + authfile)
            else:
                print('cannot auth close: ' + authfile + ' probably not opened')
        
        for x in range(0, len(authstrings)):
            authstrings[x]=authstrings[x].strip('\n')
        #print(authstrings)


def writeblockfile():
    global blocklist
    global blockfile
    global fblockfile
    if debugmode:
        print('debug mode: not writing blockfile')
        return
    print('writing new blockfile')
    fblockfile = io.open(blockfile, 'wt', buffering=1, encoding='utf-8', errors='ignore', newline='\n')
    fblockfile.writelines("%s\n" % l for l in blocklist)
    fblockfile.close
    print('done')


def rebuildblockfile():
    #this is now only called once during startup, to populate the blocklist, further updates are done with AddNewIPToBlocklist()
    global fblockfile
    global blocklist
    #blocklist.sort() #not needed, might make searching quicker but means last in isn't last block.
    print('pushing new iptables rules')
    if not debugmode:
        #do i really want to flush beforehand? what if there are other rules?
        subprocess.call(['/sbin/iptables', '--flush'])
    for line in blocklist:
        if not debugmode:
            subprocess.call(['/sbin/iptables', '-I', 'INPUT', '-s', line, '-j', 'DROP'])
        else:
            print("Rebuild/debug mode: iptables -I INPUT -s "+line+" -j DROP")
            
        print('pushing ->'+line)

    print('Saving iptables rules')
    if not debugmode:
        subprocess.call(['/sbin/iptables-save'])
    else:
        print("debug mode: iptables-save")

    timenow = time.time()
    print('done at '+time.ctime(timenow))


def AddNewIPToBlocklist(ip):
    #update iptables rules without clearing them all first
    print('adding: '+ip)
    if not debugmode:
        print('pushing ->'+ip)
        subprocess.call(['/sbin/iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'])
        subprocess.call(['/sbin/iptables-save']) #has to save because no clean exit
    else:
        print("ADD/debug mode: iptables -I INPUT -s "+ip+" -j DROP")
    return

def isIPinBlocklist(ip):
    global blocklist
    foundit = False
    for bline in blocklist:
        if bline == ip:
            foundit = True
            break
    return foundit

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
    global blocklist
    global fblockfile
    global authstrings
    global inifile
    if not checkOSisLinux():
        print("not linux, so going into debug mode")
        
    rebuild = False
    StartDir = os.getcwd().removesuffix('/')

    #listen_keyboard(on_press=press)
    welcome()
    getArgs()
    openblockfile()
    rebuildblockfile()
    x = 1
    while True:
#        try:        
            x = x + 1
            #keyboard doesn't work over ssh. just ctrl-c it instead :(
    #        if keyboard.is_pressed('escape'):
    #            print('exiting ...')
    #            break        

            if x == 10:
                x = 1
                if (authModified()):
                    openauthfile()
                    if scanandcompare():
                        writeblockfile()
            dtime(200) #rather than pause for 2 seconds, pause 10x 200ms, to prevent blocking.
        
            #lets not rebuild the blocklist every time we scan, just when we need to
            #if rebuild:
            #    rebuildblockfile()
            #    rebuild = False

#        except KeyboardInterrupt:
#            break

    ErrorArg(0)
    #should never reach here
    sys.exit(255)

if __name__ == '__main__':
    main()   

