#!/usr/bin/python

import sys
import re, uuid
import os
import readline
from pprint import pprint
from commands import *
from scapy.all import *

class Receiver:

    def __init__(self):
        self.bla = ''

    def packet_callback(self, packet):
        if ICMPv6DestUnreach in packet[0]:
            code = packet[ICMPv6DestUnreach].code
            sys.stdout.write(chr(code))
            sys.stdout.flush()
        elif ICMPv6PacketTooBig in packet[0]:
            code = packet[ICMPv6PacketTooBig].code
            mtu = packet[ICMPv6PacketTooBig].mtu
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            if mtu !=1280:
                sys.stdout.write(chr(mtu))
            sys.stdout.flush()
        elif ICMPv6TimeExceeded in packet[0]:
            code = packet[ICMPv6TimeExceeded].code
            sys.stdout.write(chr(code))
            sys.stdout.flush()
        elif ICMPv6ParamProblem in packet[0]:
            code = packet[ICMPv6ParamProblem].code
            pointer = packet[ICMPv6ParamProblem].ptr
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            if code == 0:
                sys.stdout.write(chr(pointer))
                sys.stdout.flush()
        elif ICMPv6EchoRequest in packet[0]:
            code = packet[ICMPv6EchoRequest].code
            idn = packet[ICMPv6EchoRequest].id
            seq = packet[ICMPv6EchoRequest].seq
            data = packet[ICMPv6EchoRequest].data            
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            sys.stdout.write(chr(idn))
            sys.stdout.flush()
            sys.stdout.write(chr(seq))
            sys.stdout.flush()
            sys.stdout.write(data)
            sys.stdout.flush()
        elif ICMPv6EchoReply in packet[0]:
            code = packet[ICMPv6EchoReply].code
            idn = packet[ICMPv6EchoReply].id
            seq = packet[ICMPv6EchoReply].seq
            data = packet[ICMPv6EchoReply].data            
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            sys.stdout.write(chr(idn))
            sys.stdout.flush()
            sys.stdout.write(chr(seq))
            sys.stdout.flush()
            sys.stdout.write(data)
            sys.stdout.flush()
        elif ICMPv6ND_RS in packet[0]:
            code = packet[ICMPv6ND_RS].code
            res = packet[ICMPv6ND_RS].res
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            sys.stdout.write(chr(res))
            sys.stdout.flush()
        elif ICMPv6ND_RA in packet[0]:
            code = packet[ICMPv6ND_RA].code
            chlim = packet[ICMPv6ND_RA].chlim            
            routerlifetime = packet[ICMPv6ND_RA].routerlifetime
            reachabletime = packet[ICMPv6ND_RA].reachabletime
            retranstimer = packet[ICMPv6ND_RA].retranstimer            
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            sys.stdout.write(chr(chlim))
            sys.stdout.flush()
            #print routerlifetime
            #sys.stdout.write(chr(routerlifetime))
            #sys.stdout.flush()
            sys.stdout.write(chr(reachabletime))
            sys.stdout.flush()
            sys.stdout.write(chr(retranstimer))
            sys.stdout.flush()
        elif ICMPv6ND_NS in packet[0]:
            code = packet[ICMPv6ND_NS].code
            res = packet[ICMPv6ND_NS].res
            #tgt = packet[ICMPv6ND_NS].tgt            
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            sys.stdout.write(chr(res))
            sys.stdout.flush()
            #sys.stdout.write(tgt)
            #sys.stdout.flush()
        elif ICMPv6ND_NA in packet[0]:
            code = packet[ICMPv6ND_NA].code
            res = packet[ICMPv6ND_NA].res
            #tgt = packet[ICMPv6ND_NA].tgt            
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            sys.stdout.write(chr(res))
            sys.stdout.flush()
            #sys.stdout.write(tgt)
            #sys.stdout.flush()
        elif ICMPv6ND_Redirect in packet[0]:
            code = packet[ICMPv6ND_Redirect].code
            res = packet[ICMPv6ND_Redirect].res
            #tgt = packet[ICMPv6ND_Redirect].tgt
            #dst = packet[ICMPv6ND_Redirect].dst            
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            sys.stdout.write(chr(res))
            sys.stdout.flush()
            #sys.stdout.write(tgt)
            #sys.stdout.flush()
            #sys.stdout.write(dst)
            #sys.stdout.flush()
            
    def receive(self, adr):
        sniff(filter='ip6', prn=self.packet_callback, store=0)
