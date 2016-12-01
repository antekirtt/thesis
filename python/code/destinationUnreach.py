#!/usr/bin/python

from scapy.all import *

"""
the class build Destination Unreachable messages
"""
class DestinationUnreach:
    
    def __init__(self):
        print 'Destination Unreachable'
        self.win = "2001:abcd:acad:2:b485:2aec:9447:fd83"
        self.linux = "2001:abcd:acad:2:a00:27ff:fe84:bb37"
        self.attacker = "2001:abcd:acad:1::2"
        self.firewall = "2001:abcd:acad:2::1"

    def buildPacketDestUnreach(self, ipAdr, code):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        return IPv6(dst=ipAdr,src=self.firewall)/ICMPv6DestUnreach(code=code)/IPv6(dst=self.firewall,src=ipAdr,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
    
    def execModuleDestUnreachCode0(self, exitIface, ipAdr):
        packetContainer = self.buildPacketDestUnreach(ipAdr, 0)
        send(packetContainer, iface=exitIface, verbose=False)

    def execModuleDestUnreachCode1(self, exitIface, ipAdr):
        packetContainer = self.buildPacketDestUnreach(ipAdr, 1)
        send(packetContainer, iface=exitIface, verbose=False)

    def execModuleDestUnreachCode2(self, exitIface, ipAdr):
        packetContainer = self.buildPacketDestUnreach(ipAdr, 2)
        send(packetContainer, iface=exitIface, verbose=False)

    def execModuleDestUnreachCode3(self, exitIface, ipAdr):
        packetContainer = self.buildPacketDestUnreach(ipAdr, 3)
        send(packetContainer, iface=exitIface, verbose=False)

    def execModuleDestUnreachCode4(self, exitIface, ipAdr):
        packetContainer = self.buildPacketDestUnreach(ipAdr, 4)
        send(packetContainer, iface=exitIface, verbose=False)

    def execModuleDestUnreachCode5(self, exitIface, ipAdr):
        packetContainer = self.buildPacketDestUnreach(ipAdr, 5)
        send(packetContainer, iface=exitIface, verbose=False)

    def execModuleDestUnreachCode6(self, exitIface, ipAdr):
        packetContainer = self.buildPacketDestUnreach(ipAdr, 6)
        send(packetContainer, iface=exitIface, verbose=False)

    
    def execAllLinux(self, exitIface):
        self.execModuleDestUnreachCode0(exitIface, self.linux)
        self.execModuleDestUnreachCode1(exitIface, self.linux)
        self.execModuleDestUnreachCode2(exitIface, self.linux)
        self.execModuleDestUnreachCode3(exitIface, self.linux)
        self.execModuleDestUnreachCode4(exitIface, self.linux)
        self.execModuleDestUnreachCode5(exitIface, self.linux)
        self.execModuleDestUnreachCode6(exitIface, self.linux)

    def execAllWindows(self, exitIface):
        self.execModuleDestUnreachCode0(exitIface, self.win)
        self.execModuleDestUnreachCode1(exitIface, self.win)
        self.execModuleDestUnreachCode2(exitIface, self.win)
        self.execModuleDestUnreachCode3(exitIface, self.win)
        self.execModuleDestUnreachCode4(exitIface, self.win)
        self.execModuleDestUnreachCode5(exitIface, self.win)
        self.execModuleDestUnreachCode6(exitIface, self.win)

    def execDestUnreachBadCodeWin(self,exitIface):
        for code in range(7,256):
            packetContainer = self.buildPacketDestUnreach(self.win, code)
            send(packetContainer, iface=exitIface, verbose=False)

    def execDestUnreachBadCodeLinux(self,exitIface):
        for code in range(7,256):
            packetContainer = self.buildPacketDestUnreach(self.linux, code)
            send(packetContainer, iface=exitIface, verbose=False)

    def execDestUnreachLengthLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for length in range(0,256):
            packet = IPv6(dst=self.linux,src=self.firewall)/ICMPv6DestUnreach(code=0,length=length)/IPv6(dst=self.firewall,src=self.linux,hlim=64)
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachLengthWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for length in range(0,256):
            packet = IPv6(dst=self.win,src=self.firewall)/ICMPv6DestUnreach(code=0,length=length)/IPv6(dst=self.firewall,src=self.win,hlim=128)
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachNoRouteToDestWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0,50):
            packet = IPv6(dst=self.win,src=self.attacker)/ICMPv6DestUnreach(code=0)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=1)/data
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachNoRouteToDestLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0,50):
            packet = IPv6(dst=self.linux,src=self.attacker)/ICMPv6DestUnreach(code=0)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=1)/data
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachAdrUnreachWin(self, exitIface):
        for x in range(0,50):
            packet = IPv6(dst=self.win,src=self.attacker)/ICMPv6DestUnreach(code=3)/IPv6(dst=self.attacker,src=self.win,hlim=128)/TCP(dport=80,flags="S")
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachAdrUnreachLinux(self, exitIface):
        for x in range(0,50):
            packet = IPv6(dst=self.linux,src=self.attacker)/ICMPv6DestUnreach(code=3)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/TCP(dport=80,flags="S")
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachPortUnreachWin(self, exitIface):
        for x in range(0,50):
            packet = IPv6(dst=self.win,src=self.attacker)/ICMPv6DestUnreach(code=4)/IPv6(dst=self.attacker,src=self.win,hlim=128)/TCP(dport=80,flags="S")
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachPortUnreachLinux(self, exitIface):
        for x in range(0,50):
            packet = IPv6(dst=self.linux,src=self.attacker)/ICMPv6DestUnreach(code=4)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/TCP(dport=80,flags="S")
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachCommDstAdminProhibitedWin(self, exitIface):
        for x in range(0,50):
            packet = IPv6(dst=self.win,src=self.firewall)/ICMPv6DestUnreach(code=1)/IPv6(dst=self.attacker,src=self.win,hlim=128)/TCP(dport=80,sport=49255,flags="S")
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachCommDstAdminProhibitedLinux(self, exitIface):
        for x in range(0,50):
            packet = IPv6(dst=self.linux,src=self.firewall)/ICMPv6DestUnreach(code=1)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/TCP(dport=80,sport=49255,flags="S")
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachBeyondScopeSrcAdrWin(self, exitIface):
        for x in range(0,50):
            packet = IPv6(dst=self.win,src=self.firewall)/ICMPv6DestUnreach(code=2)/IPv6(dst=self.attacker,src=self.win,hlim=128)/TCP(dport=80,sport=49255,flags="S")
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachBeyondScopeSrcAdrLinux(self, exitIface):
        for x in range(0,50):
            packet = IPv6(dst=self.linux,src=self.firewall)/ICMPv6DestUnreach(code=2)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/TCP(dport=80,sport=49255,flags="S")
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachSrcFailedPolicyWin(self, exitIface):
        for x in range(0,500):
            packet = IPv6(dst=self.win,src=self.firewall)/ICMPv6DestUnreach(code=5)/IPv6(dst=self.attacker,src=self.win,hlim=128)/TCP(dport=80,sport=49255,flags="S")
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachSrcFailedPolicyLinux(self, exitIface):
        for x in range(0,50):
            packet = IPv6(dst=self.linux,src=self.firewall)/ICMPv6DestUnreach(code=5)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/TCP(dport=80,sport=49255,flags="S")
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachRejectRouteWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0,50):
            packet = IPv6(dst=self.win,src=self.firewall)/ICMPv6DestUnreach(code=6)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=1)/data
            send(packet, iface=exitIface, verbose=False)

    def execDestUnreachRejectRouteLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0,50):
            packet = IPv6(dst=self.linux,src=self.firewall)/ICMPv6DestUnreach(code=6)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=1)/data
            send(packet, iface=exitIface, verbose=False)

    
