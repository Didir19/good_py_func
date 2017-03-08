#!/usr/bin/python
from urllib import urlopen
import urllib2
import urllib
from urlparse import urlparse
from urlparse import urlparse
from httplib import HTTPSConnection
import json
import subprocess
import filecmp

# Get Current List of IPs
url = "https://control.akamai.com/waf/api/v1/network_lists/1024_AMAZONELASTICCOMPUTECLOU"
headers = {'Authorization': 'Basic a29uYXNlY3Jlc2VhcmNoOnRsN0tIanZu', 'User-Agent': 'curl/7.21.4 (universal-apple-darwin11.0) libcurl/7.21.4 OpenSSL/0.9.8r zlib/1.2.5', 'Pragma':'no-cache', 'Content-Type': 'application/json', 'Accept': 'application/json'}
data = {}
urlparts = urlparse(url)
conn = HTTPSConnection(urlparts.netloc, 443)

conn.request("GET", urlparts.path, None, headers)
resp = conn.getresponse()
current = resp.read()
curlist = json.loads(current)

cur_list_items = curlist['list']
print "******************************"
print "Current List size: " + str(len(cur_list_items))
print "******************************\n"

f1 = open('current_list.txt','w+')
for item in cur_list_items:
	f1.write(str(item)+',\n')
f1.close

# Get New List


proc = subprocess.Popen(['curl -s https://ip-ranges.amazonaws.com/ip-ranges.json'], stdout=subprocess.PIPE, shell=True)
(out, err) = proc.communicate()

content = out

a = json.loads(content)

prefixes = a['prefixes']

new_ip_list = []
for item in prefixes:
	if item['service'] == 'EC2':
		new_ip_list.append(item['ip_prefix'])

print "******************************"
print "New List size: " + str(len(new_ip_list))
print "******************************\n"

f2 = open('new_list.txt','w+')
for item in new_ip_list:
	f2.write(str(item)+',\n')
f2.close

comp = filecmp.cmp('current_list.txt','new_list.txt')

print comp
