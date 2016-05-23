#!/usr/bin/python

import sys
import re, uuid
import os
import readline
from pprint import pprint
from commands import *
from scapy.all import *
from bitstring import *

class Receiver:

    def __init__(self, iface, adr):
        self.iface = iface
        self.ipAdr = adr

    def packet_callback(self, packet):
        if ICMPv6DestUnreach in packet[0]:
            code = packet[ICMPv6DestUnreach].code
            length = packet[ICMPv6DestUnreach].length
            unused = packet[ICMPv6DestUnreach].unused
            payload = packet[ICMPv6DestUnreach].load
            bitLength = len(format(code, 'b'))+1
            bitLength = 8
            container = self.extractBytes(code, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = 8
            container = self.extractBytes(length, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = 24
            container = self.extractBytes(unused, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = 64
            if payload != 'x':
                payload = int(payload)
                container = self.extractBytes(payload, bitLength)
                for item in container:
                    sys.stdout.write(chr(item))
                    sys.stdout.flush
        elif ICMPv6PacketTooBig in packet[0]:
            code = packet[ICMPv6PacketTooBig].code
            mtu = packet[ICMPv6PacketTooBig].mtu
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            if mtu !=1280:
                bitLength = len(format(mtu, 'b'))+1
                bitLength = 32
                container = self.extractBytes(mtu, bitLength)
                for item in container:
                    sys.stdout.write(chr(item))
                    sys.stdout.flush
        elif ICMPv6TimeExceeded in packet[0]:
            code = packet[ICMPv6TimeExceeded].code
            length = packet[ICMPv6TimeExceeded].length
            unused = packet[ICMPv6TimeExceeded].unused
            payload = packet[ICMPv6TimeExceeded].load
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            bitLength = 8
            container = self.extractBytes(length, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = 24
            container = self.extractBytes(unused, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = 64
            if payload != 'x':
                payload = int(payload)
                container = self.extractBytes(payload, bitLength)
                for item in container:
                    sys.stdout.write(chr(item))
                    sys.stdout.flush
        elif ICMPv6ParamProblem in packet[0]:
            code = packet[ICMPv6ParamProblem].code
            pointer = packet[ICMPv6ParamProblem].ptr
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            if code == 0:
                bitLength = len(format(pointer, 'b'))+1
                bitLength = 32
                container = self.extractBytes(pointer, bitLength)
                for item in container:
                    sys.stdout.write(chr(item))
                    sys.stdout.flush
        elif ICMPv6EchoRequest in packet[0]:
            code = packet[ICMPv6EchoRequest].code
            idn = packet[ICMPv6EchoRequest].id
            seq = packet[ICMPv6EchoRequest].seq
            data = packet[ICMPv6EchoRequest].data
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            bitLength = len(format(idn, 'b'))+1
            bitLength = 16
            container = self.extractBytes(idn, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = len(format(seq, 'b'))+1
            bitLength = 16
            container = self.extractBytes(seq, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            if(data):
                #this because scapy internals transform it in string before sending
                data = int(data)
                bitLength = len(format(data, 'b'))+1
                bitLength = 64
                container = self.extractBytes(data, bitLength)
                for item in container:
                    sys.stdout.write(chr(item))
                    sys.stdout.flush
        elif ICMPv6EchoReply in packet[0]:
            code = packet[ICMPv6EchoReply].code
            idn = packet[ICMPv6EchoReply].id
            seq = packet[ICMPv6EchoReply].seq
            data = packet[ICMPv6EchoReply].data
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            bitLength = len(format(idn, 'b'))+1
            bitLength = 16
            container = self.extractBytes(idn, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = len(format(seq, 'b'))+1
            bitLength = 16
            container = self.extractBytes(seq, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            if(data):
                #this because scapy internals transform it in string before sending
                data = int(data)
                bitLength = len(format(data, 'b'))+1
                bitLength = 64
                container = self.extractBytes(data, bitLength)
                for item in container:
                    sys.stdout.write(chr(item))
                    sys.stdout.flush
        elif ICMPv6ND_RS in packet[0]:
            code = packet[ICMPv6ND_RS].code
            res = packet[ICMPv6ND_RS].res
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            bitLength = len(format(res, 'b'))+1
            bitLength = 32
            container = self.extractBytes(res, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
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
            bitLength = len(format(reachabletime, 'b'))+1
            bitLength = 32
            container = self.extractBytes(reachabletime, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = len(format(retranstimer, 'b'))+1
            bitLength = 32
            container = self.extractBytes(retranstimer, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
        elif ICMPv6ND_NS in packet[0]:
            code = packet[ICMPv6ND_NS].code
            res = packet[ICMPv6ND_NS].res
            #tgt = packet[ICMPv6ND_NS].tgt
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            #bitLength = len(format(res, 'b'))+1
            #it seems that scapy neighbor solicitation reserved field use only 24 bits(ver2.3.2)
            #requires version 2.3.2-dev
            bitLength = 32
            container = self.extractBytes(res, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
        elif ICMPv6ND_NA in packet[0]:
            code = packet[ICMPv6ND_NA].code
            res = packet[ICMPv6ND_NA].res
            #tgt = packet[ICMPv6ND_NA].tgt
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            bitLength = len(format(res, 'b'))+1
            bitLength = 24
            container = self.extractBytes(res, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
        elif ICMPv6ND_Redirect in packet[0]:
            code = packet[ICMPv6ND_Redirect].code
            res = packet[ICMPv6ND_Redirect].res
            #tgt = packet[ICMPv6ND_Redirect].tgt
            #dst = packet[ICMPv6ND_Redirect].dst
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            bitLength = len(format(res, 'b'))+1
            bitLength = 32
            container = self.extractBytes(res, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            #sys.stdout.write(tgt)
            #sys.stdout.flush()
            #sys.stdout.write(dst)
            #sys.stdout.flush()

    def receive(self):
        sniff(iface=self.iface, filter='ip6 and dst '+self.ipAdr, prn=self.packet_callback, store=0)

    """
    transform int in the binary strings format of variable length, then for each byte transform back in int
    """
    def extractBytes(self, data, bitsLength):
        binary = BitArray(uint=data, length=bitsLength)
        bytesNum = bitsLength/8
        container = []
        for x in range(0, bytesNum):
            f = x*8
            s = (x+1)*8
            value = binary[f:s]
            container.append(int(value.bin, 2))
        return container
