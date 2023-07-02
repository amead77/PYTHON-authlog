#
#
# This script just prints out the blocklist contents in human readable format
# Assumes blocklist.txt is in the same directory as the script
#
#
#
import os, sys, io, time
import pickle #for saving blocklist
import datetime #for timestamping#


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

#######################
def PrintBlockList():
    global aBlocklist
    print('printing blocklist')
    for i in range(len(aBlocklist)):
        print(aBlocklist[i].ip+':')
        for x in range(len(aBlocklist[i].aDateTime)):
            print('-->'+ReverseDateTime(aBlocklist[i].aDateTime[x])+" reason: "+aBlocklist[i].aReason[x])


#######################
def TimeStamp():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))


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
def OpenBlockList():
    #read in the blocklist file to aBlocklist array
    global aBlocklist
    global blockfile

    #aBlocklist = [] #should be the first time this is called. / wasn't though was it

    if (os.path.isfile(blockfile)):
        try:
            with open(blockfile, 'rb') as fblockfile:
                aBlocklist = pickle.load(fblockfile)
        except:
            print('problem loading blocklist')

    else:
        print('blocklist file not found')


#######################
def CheckIsLinux():
    #this is because it is designed to run on Linux, but I also code on Windows, in which case I don't want it to run all the code
    if not sys.platform.startswith('linux'):
        debugmode = True
        return False
    else:
        return True


########################################################
####################### [ MAIN ] #######################
########################################################
def main():
    global StartDir
    global blockcount
    global blockfile
    AuthPos = 0
    global slash
    slash = '/'
    StartDir = os.getcwd().removesuffix(slash)

    blockfile = StartDir+slash+'blocklist.txt'
    if not CheckIsLinux():
        print("not linux, so going into debug mode")
        slash = '\\'
        
    rebuild = False
    StartDir = os.getcwd().removesuffix(slash)
    OpenBlockList()
    PrintBlockList()
    sys.exit(255)

if __name__ == '__main__':
    main()   
