#todo
#
# failure count is ignored. implement*****
# --create record array: ip, fail count
# --during scan increment fail count on every find
# --at end of scan block based on failcount
# --maybe also consider what is already in the blocklist
# keyboard only works locally. disabled for now. find SSH (and) RPi compatible workaround.
# inifile isn't actually used or even written to
# auth needs sorting
#
#notes
#'iptables -I INPUT -s '+slBlocklist.Strings[i]+' -j DROP'

from getpass import getpass
import os, argparse, sys, io, time, subprocess
#from sshkeyboard import listen_keyboard, stop_listening

#import keyboard
#from subprocess import call

#debugmode = True
debugmode = False

version = "2023-01-27 22:22:44"
#2023-02-12 21:37:26

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


#is_root()
#   geteuid: get effective user id, getuid: get user actual id
#   with: os.geteuid() == 0 returns true/false, else uid number
def is_root(): 
    return os.geteuid() == 0


def test_sudo(pwd=""):
    args = "sudo -S echo OK".split()
    kwargs = dict(stdout=subprocess.PIPE,
                  encoding="ascii")
    if pwd:
        kwargs.update(input=pwd)
    try:
        cmd = subprocess.run(args, **kwargs)
    except:
        print("probs")
    finally:
        pass

    return ("OK" in cmd.stdout)


def prompt_sudo():#with == 0 returns true/false, else uid number
    ok = is_root() or test_sudo()
    if not ok:
        try:
            pwd = getpass("password: ")
        except:
            print("abandoning sudo")
        finally:
            pass

        ok  = test_sudo(pwd)
    return ok
    


if prompt_sudo():
    print("Access granted !")
else:
    print("Access denied !")
    ErrorArg(3)


def welcome():
    if debugmode:
        print("EUID: ", os.geteuid())
        dtime(2000)
    print('\n[==-- Wheel reinvention society presents: authlogger! --==]\n')
    print('Does some of what other, better, programs do, but worse!\n')
    print('version: '+version)
    print("Press ESCAPE to exit, or just crash out with ctrl-c, whatever")
    if not is_root(): 
        if not debugmode: 
            #ErrorArg(3)
            prompt_sudo()


def FileLineCount(ff):
    count=0
    try:
        with open(ff,'rb') as tf:
            for line in tf:
                count = count + 1
        tf.close()
    except:
        count=-1
#    finally:
    return count


#depreciated since py3.9, 'cept i'm on 3.7
def RemoveTrailingSlash(s):
    if ((sys.version_info[0] == 3) and (sys.version_info[1] < 9)):    
        if s.endswith('/'):
            s = s[0:-1]
    else:
        s=s.removesuffix('/')    
    return s    


def HELP():
    print("**something went wrong. I don't know what, so if you started with no parameters it probably means a file didn't exist or you ran as a normie rather than root\n")
    print("auth.log file to scan            : -a, --authfile <filename>")
    print("blocklist file with IPs          : -b, --blockfile <filename>")
    print("number of attempts to block      : -f, --failcount <2>")
    print("inifile with settings (not req.) : -i, --inifile <filename>")
    print("local ip address range to ignore : -l, --localip <192.168.>")


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
    parser.add_argument('-f', '--failcount', action='store', type=int, help='number of login failures to block IP (defaults to 2)', default=2)
    parser.add_argument('-i', '--inifile', action='store', help='.ini file and path', default='')
    parser.add_argument('-l', '--localip', action='store', help='local IP range to ignore (default 192.168.)', default='192.168.')
    #parser.add_argument('-p', '--PassThru', dest='PassThru', action='store', help='parameters to pass to CMD', default='')
    args = parser.parse_args()

    blockfile = args.blockfile
    localip = args.localip
    authfile = args.authfile
    failcount = args.failcount
    inifile = args.inifile

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
    if (os.path.isfile(blockfile)):
        fblockfile = io.open(blockfile, 'rt', buffering=1, encoding='utf-8', errors='ignore', newline='\n')
        blocklist=fblockfile.readlines()
        for x in range(0, len(blocklist)):
            blocklist[x]=blocklist[x].strip('\n')
        #print(blocklist)
        fblockfile.close


def openauthfile():
    global authfile
    global blocklist
    global authstrings
    #print('auth open')
    if (os.path.isfile(authfile)):
        try:
            fauthfile = io.open(authfile, 'rt', buffering=1, encoding='utf-8', errors='ignore', newline='\n')
            authstrings=fauthfile.readlines()
        except:
            pass
        finally:
            fauthfile.close
        
        for x in range(0, len(authstrings)):
            authstrings[x]=authstrings[x].strip('\n')
        #print(authstrings)


def rebuildblockfile():
    global fblockfile
    global blocklist
    blocklist.sort()
    print('pushing new iptables rules')
    subprocess.call(['/sbin/iptables', '--flush'])
    for line in blocklist:
        if not debugmode:
            subprocess.call(['/sbin/iptables', '-I', 'INPUT', '-s', line, '-j', 'DROP'])
        else:
            print("debug mode")
            
        print('pushing ->'+line)

    print('writing new blockfile')
    fblockfile = io.open(blockfile, 'wt', buffering=1, encoding='utf-8', errors='ignore', newline='\n')
    fblockfile.writelines("%s\n" % l for l in blocklist)
    fblockfile.close
    print('Saving iptables rules')
    if not debugmode:
        subprocess.call(['/sbin/iptables-save'])
    else:
        print("debug mode: iptables-save")

    timenow = time.time()
    print('done at '+time.ctime(timenow))


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
            foundit = False
            for bline in blocklist:
                if bline == aline:
                    foundit = True
                    break
            if not foundit:            
                print('adding: '+aline)
                blocklist.append(aline)
                newblock = True

    return newblock


def dtime(cmd):
    cmd = float(cmd/1000)
    time.sleep(cmd)
    return

#def key_capture_thread():
#    global keep_going
#    input()
#    keep_going = False

def press(key):
    print(f"'{key}' pressed")
#    if key == "escape":
#        stop_listening()
#        ErrorArg(0)


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

    rebuild = False
    StartDir = RemoveTrailingSlash(os.getcwd())

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
                openauthfile()
                if scanandcompare():
                    rebuild = True
            dtime(200) #rather than pause for 2 seconds, pause 10x 200ms, to prevent blocking.
        
            if rebuild:
                rebuildblockfile()
                rebuild = False
#        except KeyboardInterrupt:
#            break

    ErrorArg(0)
    #should never reach here
    sys.exit(255)

if __name__ == '__main__':
    main()   

