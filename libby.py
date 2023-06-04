from getpass import getpass
import os, argparse, sys, io, time, subprocess

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


def dtime(cmd):
    cmd = float(cmd/1000)
    time.sleep(cmd)
    return


def checkOSisLinux():
    #this is because it is designed to run on Linux, but I also code on Windows, in which case I don't want it to run all the code
    if not sys.platform.startswith('linux'):
        debugmode = True
        return False
    else:
        return True

#if prompt_sudo():
#    print("Access granted !")
#else:
#    print("Access denied !")
#    ErrorArg(3)


def HELP():
    print("**something went wrong. I don't know what, so if you started with no parameters it probably means a file didn't exist or you ran as a normie rather than root\n")
    print("auth.log file to scan            : -a, --authfile <filename>")
    print("blocklist file with IPs          : -b, --blockfile <filename>")
    print("number of attempts to block      : -f, --failcount <2>")
    print("inifile with settings (not req.) : -i, --inifile <filename>")
    print("local ip address range to ignore : -l, --localip <192.168.>")
    print("Remember: must run as sudo/root or it cannot block IPs\n")


#depreciated since py3.9, 'cept i'm on 3.7
#def RemoveTrailingSlash(s):
#    if ((sys.version_info[0] == 3) and (sys.version_info[1] < 9)):    
#        if s.endswith('/'):
#            s = s[0:-1]
#    else:
#        s=s.removesuffix('/')    
#    return s    

#is_root()
#   geteuid: get effective user id, getuid: get user actual id
#   with: os.geteuid() == 0 returns true/false, else uid number


#def is_root(): 
#    if not debugmode:
#        return os.geteuid() == 0
#    else:
#        return 0


#def test_sudo(pwd=""):
#    args = "sudo -S echo OK".split()
#    kwargs = dict(stdout=subprocess.PIPE,
#                  encoding="ascii")
#    if pwd:
#        kwargs.update(input=pwd)
#    try:
#        cmd = subprocess.run(args, **kwargs)
#    except:
#        print("probs")
#    finally:
#        pass
#
#    return ("OK" in cmd.stdout)


#def prompt_sudo():#with == 0 returns true/false, else uid number
#    if not debugmode:
#        ok = is_root() or test_sudo()
#        if not ok:
#            try:
#                pwd = getpass("password: ")
#            except:
#                print("abandoning sudo")
#            finally:
#                pass
#
#            ok  = test_sudo(pwd)
#        return ok
#    else:
#        return True