#!/usr/bin/python

import urllib2
import re
import time
import sys
import threading
import Queue
import re
import resource
import dns.resolver

urlTemplate = 'http://www.ipvoid.com/scan/'
badipsURLRoot = 'https://www.badips.com/get/info/'
stopForumSpamURLRoot = 'http://api.stopforumspam.org/api?ip='
myQueue = Queue.Queue()
myResultsQueue = Queue.Queue()

RESULTS_HEADER = 'IP\tIP-VOID-RESULTS\tPROJECT-HONEYPOT-RESULTS\tBAD-IPS-RESULTS\tSTOP-FORUM-SPAM'

# 1zjrq9y8bxt5kh # Stop Spam Forum API KEY (Currently Not Needed)

APIKEY = 'hkphkajdxprl'

THREAT_MAP = {'0' : 'Search Engine', '1' : 'Suspicious', '2' : 'Harvester', '3' : 'Suspicious Harvester', '4' : 'Comment Spammer', '5' : 'Suspicious Comment Spammer', '6' : 'Harvester / Comment Spammer', '7' : 'Suspicious / Harvester / Comment Spammer'}

NUM_THREADS = 100


def reverseIP(iAddress):
    results = ''
    splittedAddress = iAddress.split('.')
    splittedAddress.reverse()
    for item in splittedAddress:
        results += item + '.'
    return results[:len(results)-1]


def fetchResponse(iAddress):
    try:
        response = urllib2.urlopen(urlTemplate + iAddress + '/')
        html = response.read()
        return html
    except:
        return "Invalid Response"

def resolveSpecial(iReversedIP):
    try:
        answers = dns.resolver.query(APIKEY + '.' + iReversedIP + '.dnsbl.httpbl.org')
        add =  str(answers.response.answer[0].items[0])
        last = add.split('.')[3]
        return THREAT_MAP[last]
    except:
        return 'Not Listed'

def fetchBadIPResponse(iAddress):
    try:
	   response = urllib2.urlopen(badipsURLRoot + iAddress)
	   data = response.read()
	   return data
    except:
	   return 'Not Listed' 

def fetchStopForumSpam(iAddress):
    try:
        response = urllib2.urlopen(stopForumSpamURLRoot + iAddress)
        data = response.read()
        return data
    except:
        return 'Not Listed'


def checkAddressCallBack():
    while not myQueue.empty():
        currentAddress = myQueue.get_nowait()
        response = fetchResponse(currentAddress)
        match = re.search('(BLACKLISTED [0-9]+/[0-9]+)',response)
        if match:
            myLine =  currentAddress + '\t' + match.group(0)
        else:
            myLine =  currentAddress +  '\tNot Listed'
        httpBLData = resolveSpecial(reverseIP(currentAddress))
        myLine = myLine + '\t' + httpBLData
        badIPData = fetchBadIPResponse(currentAddress)
        ipmatch = re.search('Categories\":\[\".*?\]',badIPData)
        if ipmatch:
            myLine = myLine + '\tThreat ' + ipmatch.group(0)
        else:
            myLine = myLine + '\tNot Listed'
        stopForumSpamData = fetchStopForumSpam(currentAddress)
        if stopForumSpamData.find('<appears>yes</appears>') >= 0:
            frequencyMatch = re.search('<frequency>([0-9]+)', stopForumSpamData)
            lastSeenMatch = re.search('<lastseen>([^<]+)</lastseen>',stopForumSpamData)
            if frequencyMatch:
                myLine = myLine + '\tListed (Frequency: ' + frequencyMatch.group(1)
            if lastSeenMatch:
                myLine = myLine + ', Last Seen: ' + lastSeenMatch.group(1) + ')'
        else:
                myLine = myLine + '\tNot Listed'
        myResultsQueue.put_nowait(myLine)

def main():
    if len(sys.argv) != 3:
        print "Usage: checkBlacklists.py [-f] <file> | -ip <IP_ADDRESS>"
        sys.exit(1)

    if sys.argv[1] not in ['-ip','-f']:
        print "Usage: checkBlacklists.py [-f] <file> | -ip <IP_ADDRESS>"
        sys.exit(1)
        
    if sys.argv[1] == '-ip':
        myQueue.put_nowait(sys.argv[2])
        checkAddressCallBack()
        print RESULTS_HEADER
        print myResultsQueue.get_nowait()
        sys.exit(0)

    if sys.argv[1] == '-f':
        f = open(sys.argv[2],'r')
        contents = f.readlines()
        for line in contents:
            myQueue.put(line.rstrip('\n'))
        Threads = []
        for i in range(0, NUM_THREADS):
            t = threading.Thread(target=checkAddressCallBack, args=[])
            Threads.append(t)
        for t in Threads:
            try:
                t.start()
            except:
                print "cound not start poor thread"
                Threads.remove(t)
        for t in Threads:
            if t.isAlive(): t.join()
        print "Done."
        o = open('ip_blacklist_results.csv','w+')
        o.write(RESULTS_HEADER + '\n')
        while not myResultsQueue.empty():
            o.write(myResultsQueue.get_nowait() + '\n')
        o.close()
main()


