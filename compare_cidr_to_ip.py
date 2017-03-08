from netaddr import *
from subprocess import call
ipset=IPSet()
with open('azurelist.txt','rb') as azure:
        for line in azure:
            ipset.add(line.rstrip())


with open('iplist.txt', 'rb') as iptocheck:
    for ip2 in iptocheck:
            ipt = ip2.rstrip()
            if ipt in ipset:
                print "IN "+ip2.rstrip()+" in Azure"
                call(["host", ip2.rstrip()])
            else:
                print "NOT IN "+ip2.rstrip()+" NOT in Azure"

