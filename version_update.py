#this script is to find the line in a python script that has the version number,
#and update it to the current date/time and version.
#looks for: version = "v01.0-2023/08/25r00"
#and updates it to: version = "v01.0-2023/08/25r01"
#if the date has changed, also update the date part of the version number


################################################
### must revisit this to make it only change the version line, not the whole thing
################################################


import os, sys, datetime, time

def GetVersion(inputstr):
    #return the version number from the input string
    tmp = inputstr.split('"')
    tmp = tmp[1].split('-')
    return tmp[0]


def GetDate(inputstr):
    #return the date from the input string
    tmp = inputstr.split('"')
    tmp = tmp[1].split('-')
    tmp = tmp[1].split('r')
    return tmp[0]

def GetRevision(inputstr):
    #return the revision number from the input string
    tmp = inputstr.split('"')
    tmp = tmp[1].split('-')
    tmp = tmp[1].split('r')
    return tmp[1]


if __name__ == '__main__':
    filename = ''
    replacestr = ''
    vstringfound = False #triggers if version string is auto configured
    found = False
    if len(sys.argv) < 2:
        print('Usage: version_update.py <filename>')
        sys.exit(1)

    filename = sys.argv[1]
    print('filename: ' + filename)

    if not os.path.isfile(filename):
        print('file not found: ' + filename)
        sys.exit(1)

    with open(filename, 'r') as f:
        data = f.readlines()
        f.close()

    for i in range(len(data)):
        if data[i].find('#AUTO'+'-V') >= 0: vstringfound = True #done this way to prevent finding itself
        if (data[i].find('version = "v') >= 0) and (vstringfound):
            #print('found version string: ' + data[i])
            version = GetVersion(data[i])
            revision = GetRevision(data[i])
            revision = int(revision) + 1
            now = datetime.datetime.now()
            now = now.strftime("%Y/%m/%d")
            date = GetDate(data[i])
            if date != now: revision = 0

            newversion = 'version = "'+version + '-' + now + 'r' + str(revision).zfill(2)+'"'
            print('new      : ' + newversion+'<--')
            print('previous : ' + data[i])
            data[i] = newversion + '\n'
            found = True
            break
    if found:
        time.sleep(1.5) #need to wait for the file to be closed before writing to it
        outfile = open(filename, 'w')
        outfile.writelines(data)
        outfile.close()
        print('file updated: ' + filename)
    else:
        print('version string not found in file or not AUTO-V: ' + filename)
