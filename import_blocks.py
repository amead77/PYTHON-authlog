from getpass import getpass
import os, argparse, sys, io, time, subprocess
from libby import *
import signal #for ctrl-c detection
import pickle #for saving blocklist
import datetime #for timestamping#

class cBlock:
    def __init__(self, datetime=None, ip=None): #failcount not needed as count of datetime array will show failures
        self.datetime = []
        self.ip = ip

    def add_datetime(self, datetime):
        self.datetime.append(datetime)


aBlocklist = [] #array of cBlock objects

def SaveBlockList():
    #print('saving blocklist (dump)')
    #save the blocklist array to the blocklist file
    global blocklist
    global blockfile
    #for x in range(0, len(aBlocklist)):
    #    for y in range(0, len(aBlocklist[x].datetime)):
    #        print(aBlocklist[x].ip+' '+aBlocklist[x].datetime[y])
    print("---")
    print('saving blocklist')
    with open(blockfile, "wb") as fblockfile:
        pickle.dump(aBlocklist, fblockfile)
    fblockfile.close()

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
            
        except:
            print('blocklist file is corrupt, will be overwritten on save')

    else:
        print('blocklist file not found, will be created on save')


def AddNewIPToBlocklist(ip):
    global aBlocklist
    timeblocked = time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))
    #update iptables rules without clearing them all first
    ip=ip.strip()
    print('adding: "'+ip+'"')
    aBlocklist.append(cBlock(ip=ip))
    aBlocklist[len(aBlocklist)-1].add_datetime(timeblocked)


def ReadOldBlocks():
    #read in the old blocklist file to aBlocklist array
    global aBlocklist
    global blockfile
    global oldblockfile
    with open(oldblockfile, 'r') as fblockfile:
        for line in fblockfile:
            AddNewIPToBlocklist(line)
    fblockfile.close()

def main():
    global aBlocklist
    global blockfile
    global oldblockfile
    blockfile = 'blockie.txt'
    oldblockfile = 'old.txt'

    OpenBlockList()
    ReadOldBlocks()
    SaveBlockList()

if __name__ == '__main__':
    main()