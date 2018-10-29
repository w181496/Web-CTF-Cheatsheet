#!/usr/bin/python
import sys
import socket

def getDec(parts):
    dec = 0
    w = 1
    for i in range(len(parts)):
        dec += int(parts[i]) * (256 ** ((3 - i)))
    return dec

def getHex(parts):
    hx = ''
    for i in range(len(parts)):
        if i != 0: hx += '.'
        hx += hex(int(parts[i]))
    return hx

def getOct(parts):
    ot = ''
    for i in range(len(parts)):
        if i != 0: ot += '.'
        ot += oct(int(parts[i]))
    return ot

def getBin(parts):
    bi = ''
    for i in range(len(parts)):
        if i != 0: bi += '.'
        bi += bin(int(parts[i]))
    return bi

if len(sys.argv) < 2:
    host = raw_input('input host:')
else:
    host = sys.argv[1]
ip = socket.gethostbyname(host)

print "IP Address:", ip

print

parts = ip.split('.')

dec = getDec(parts)

print "Decimal IP:", dec

print

hx = getHex(parts)

print "Hex IP:", hex(dec)
print "Dotted Hex IP:", hx

print

print "Oct IP", oct(dec)
print "Dotted Oct IP:", getOct(parts)

print

print "xip.io:", ip + ".xip.io"
