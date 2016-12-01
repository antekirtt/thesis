#!/usr/bin/python

from scapy.all import *

"""
the class build Time Exceeded messages
"""
class TimeExceeded:
    
    def __init__(self):
        print 'Time Exceeded'
        self.win = "2001:abcd:acad:2:b485:2aec:9447:fd83"
        self.linux = "2001:abcd:acad:2:a00:27ff:fe84:bb37"
        self.attacker = "2001:abcd:acad:1::2"
        self.firewall = "2001:abcd:acad:2::1"

    def execModuleTimeExceededBadCodeWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for code in range(2, 256):
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6TimeExceeded(code=code)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleTimeExceededBadCodeLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for code in range(2, 256):
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6TimeExceeded(code=code)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleTimeExceededHopLimitWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0, 50):
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6TimeExceeded(code=0)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleTimeExceededHopLimitLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0, 50):
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6TimeExceeded(code=0)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleTimeExceededFragmentReassemblyWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0, 50):
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6TimeExceeded(code=1)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleTimeExceededFragmentReassemblyLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0, 50):
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6TimeExceeded(code=1)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleTimeExceededLengthWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0, 256):
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6TimeExceeded(code=0,length=x)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleTimeExceededLengthLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0, 256):
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6TimeExceeded(code=0,length=x)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    
