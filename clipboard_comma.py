#!/usr/bin/python
import subprocess

def getClipboardData():
 p = subprocess.Popen(['pbpaste'], stdout=subprocess.PIPE)
 retcode = p.wait()
 data = p.stdout.read()
 return data

def setClipboardData(data):
 p = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
 p.stdin.write(data)
 p.stdin.close()
 retcode = p.wait()

a =  getClipboardData()
a= a.split('\n')
b='('
for line in a:	
	b= b+"'"+line+"',"
b=b[:-1]
b= b+')'
setClipboardData(b)

