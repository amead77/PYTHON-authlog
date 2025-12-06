from getpass import getpass
import os, argparse, sys, io, time, subprocess
import signal #for ctrl-c detection
import pickle #for saving blocklist
import datetime #for timestamping#

class cBlock:
    def __init__(self, aDateTime=None, ip=None, reason = None): #failcount not needed as count of datetime array will show failures
        self.aDateTime = []
        self.ip = ip
        self.reason = []

    def add_datetime(self, aDateTime):
        self.aDateTime.append(aDateTime)

    def add_reason(self, reason):
        self.reason.append(reason)

    def add_datetime(self, datetime):
        self.aDateTime.append(datetime)


aBlocklist = [] #array of cBlock objects

def SaveBlockList():
    #print('saving blocklist (dump)')
    #save the blocklist array to the blocklist file
    global blocklist
    global blockfile
    #for x in range(0, len(aBlocklist)):
    #    for y in range(0, len(aBlocklist[x].aDateTime)):
    #        print(aBlocklist[x].ip+' '+aBlocklist[x].aDateTime[y])
    print("---")
    print('saving blocklist')
    with open(blockfile, "wb") as fblockfile:
        pickle.dump(aBlocklist, fblockfile)
    #fblockfile.close()


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
            #fblockfile.close()
            
        except:
            print('blocklist file is corrupt, will be overwritten on save')

    else:
        print('blocklist file not found, will be created on save')


def CheckBlocklist(ip, timeblocked):
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
            print('adding datetime: '+ip)
            aBlocklist[dtfound].add_datetime(timeblocked)
            aBlocklist[dtfound].add_reason('add datetime')
        else:
            print('adding: '+ip)
            aBlocklist.append(cBlock(ip=ip))
            aBlocklist[len(aBlocklist)-1].add_datetime(timeblocked)
            aBlocklist[len(aBlocklist)-1].add_reason('new ip [import_blocks]')


def AddNewIPToBlocklist(ip):
    global aBlocklist
    timeblocked = time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))
    #update iptables rules without clearing them all first
    ip=ip.strip()
    CheckBlocklist(ip, timeblocked)


def ReadOldBlocks():
    #read in the old blocklist file to aBlocklist array
    global aBlocklist
    global blockfile
    global oldblockfile
    with open(oldblockfile, 'r') as fblockfile:
        for line in fblockfile:
            AddNewIPToBlocklist(line)
    #fblockfile.close()

def main():
    global aBlocklist
    global blockfile
    global oldblockfile
    blockfile = 'blocklist.txt'
    oldblockfile = 'old.txt'

    OpenBlockList()
    ReadOldBlocks()
    SaveBlockList()

if __name__ == '__main__':
    main()