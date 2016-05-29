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
        self.containerBits = ''

    def packet_callback(self, packet):
        if ICMPv6DestUnreach in packet[0]:
            code = packet[ICMPv6DestUnreach].code
            length = packet[ICMPv6DestUnreach].length
            unused = packet[ICMPv6DestUnreach].unused
            payload = packet[ICMPv6DestUnreach].load
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
            bitLength = 16
            container = self.extractBytes(idn, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = 16
            container = self.extractBytes(seq, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            if(data):
                #this because scapy internals transform it in string before sending
                data = int(data)
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
            bitLength = 16
            container = self.extractBytes(idn, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = 16
            container = self.extractBytes(seq, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            if(data):
                #this because scapy internals transform it in string before sending
                data = int(data)
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
            bitLength = 32
            container = self.extractBytes(res, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
        elif ICMPv6ND_RA in packet[0]:
            code = packet[ICMPv6ND_RA].code
            chlim = packet[ICMPv6ND_RA].chlim
            M = packet[ICMPv6ND_RA].M
            O = packet[ICMPv6ND_RA].O
            H = packet[ICMPv6ND_RA].H
            prf = packet[ICMPv6ND_RA].prf
            P = packet[ICMPv6ND_RA].P
            res = packet[ICMPv6ND_RA].res
            routerlifetime = packet[ICMPv6ND_RA].routerlifetime
            reachabletime = packet[ICMPv6ND_RA].reachabletime
            retranstimer = packet[ICMPv6ND_RA].retranstimer
            if code not in range(1,7):
                bitLength = 8
                container = self.extractBytes(code, bitLength)
                for item in container:
                    sys.stdout.write(chr(item))
                    sys.stdout.flush
            bitLength = 8
            container = self.extractBytes(chlim, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            if code == 1:
                self.containerBits += str(M)
                if len(self.containerBits) == 8:
                    container = self.extractBytes(int(self.containerBits, 2), 8)
                    for item in container:
                        sys.stdout.write(chr(item))
                        sys.stdout.flush
                    self.containerBits = ''
            elif code == 2:
                self.containerBits += str(O)
                if len(self.containerBits) == 8:
                    container = self.extractBytes(int(self.containerBits, 2), 8)
                    for item in container:
                        sys.stdout.write(chr(item))
                        sys.stdout.flush
                    self.containerBits = ''
            elif code == 3:
                self.containerBits += str(H)
                if len(self.containerBits) == 8:
                    container = self.extractBytes(int(self.containerBits, 2), 8)
                    for item in container:
                        sys.stdout.write(chr(item))
                        sys.stdout.flush
                    self.containerBits = ''
            elif code == 4:
                tmpBit = BitArray(uint=prf, length=2)
                self.containerBits += tmpBit.bin
                if len(self.containerBits) == 8:
                    container = self.extractBytes(int(self.containerBits, 2), 8)
                    for item in container:
                        sys.stdout.write(chr(item))
                        sys.stdout.flush
                    self.containerBits = ''
            elif code == 5:
                self.containerBits += str(P)
                if len(self.containerBits) == 8:
                    container = self.extractBytes(int(self.containerBits, 2), 8)
                    for item in container:
                        sys.stdout.write(chr(item))
                        sys.stdout.flush
                    self.containerBits = ''
            elif code == 6:
                tmpBit = BitArray(uint=res, length=2)
                self.containerBits += tmpBit.bin
                if len(self.containerBits) == 8:
                    container = self.extractBytes(int(self.containerBits, 2), 8)
                    for item in container:
                        sys.stdout.write(chr(item))
                        sys.stdout.flush
                    self.containerBits = ''
            bitLength = 16
            container = self.extractBytes(routerlifetime, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = 32
            container = self.extractBytes(reachabletime, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = 32
            container = self.extractBytes(retranstimer, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
        elif ICMPv6ND_NS in packet[0]:
            code = packet[ICMPv6ND_NS].code
            res = packet[ICMPv6ND_NS].res
            tgt = packet[ICMPv6ND_NS].tgt
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            #it seems that scapy neighbor solicitation reserved field use only 24 bits(ver2.3.2)
            #requires version 2.3.2-dev
            bitLength = 32
            container = self.extractBytes(res, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = 128
            container = self.extractBytesAddress(tgt, bitLength)
            if container:
                for item in container:
                    sys.stdout.write(chr(item))
                    sys.stdout.flush
        elif ICMPv6ND_NA in packet[0]:
            code = packet[ICMPv6ND_NA].code
            res = packet[ICMPv6ND_NA].res
            R = packet[ICMPv6ND_NA].R
            S = packet[ICMPv6ND_NA].S
            O = packet[ICMPv6ND_NA].O
            tgt = packet[ICMPv6ND_NA].tgt
            if code not in range(1,4):
                sys.stdout.write(chr(code))
                sys.stdout.flush()
            bitLength = 24
            container = self.extractBytes(res, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            if code == 1:
                self.containerBits += str(R)
                if len(self.containerBits) == 8:
                    container = self.extractBytes(int(self.containerBits, 2), 8)
                    for item in container:
                        sys.stdout.write(chr(item))
                        sys.stdout.flush
                    self.containerBits = ''
            if code == 2:
                self.containerBits += str(S)
                if len(self.containerBits) == 8:
                    container = self.extractBytes(int(self.containerBits, 2), 8)
                    for item in container:
                        sys.stdout.write(chr(item))
                        sys.stdout.flush
                    self.containerBits = ''
            if code == 3:
                self.containerBits += str(O)
                if len(self.containerBits) == 8:
                    container = self.extractBytes(int(self.containerBits, 2), 8)
                    for item in container:
                        sys.stdout.write(chr(item))
                        sys.stdout.flush
                    self.containerBits = ''
            bitLength = 128
            container = self.extractBytesAddress(tgt, bitLength)
            if container:
                for item in container:
                    sys.stdout.write(chr(item))
                    sys.stdout.flush
        elif ICMPv6ND_Redirect in packet[0]:
            code = packet[ICMPv6ND_Redirect].code
            res = packet[ICMPv6ND_Redirect].res
            tgt = packet[ICMPv6ND_Redirect].tgt
            dst = packet[ICMPv6ND_Redirect].dst
            sys.stdout.write(chr(code))
            sys.stdout.flush()
            bitLength = 32
            container = self.extractBytes(res, bitLength)
            for item in container:
                sys.stdout.write(chr(item))
                sys.stdout.flush
            bitLength = 128
            container = self.extractBytesAddress(tgt, bitLength)
            if container:
                for item in container:
                    sys.stdout.write(chr(item))
                    sys.stdout.flush
            bitLength = 128
            container = self.extractBytesAddress(dst, bitLength)
            if container:
                for item in container:
                    sys.stdout.write(chr(item))
                    sys.stdout.flush

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

    """
    split and strip out columns, check if the chunk is 0 or 1, added to send a regular ipv6 address, transform in binary 
    using the hex value and build the container with each int value
    """
    def extractBytesAddress(self, data, bitsLength):
        dataList = data.split(":")
        dataString = ''
        container = []
        for d in dataList:
            if d and d != '0' and d != '1':
                #len is 1 because scapy takes away leading 0s in ipv6 address
                if len(d) == 1:
                    d = '0'+d
                binary = BitArray(hex=d)
                for x in range(0, len(binary)/8):
                    f = x*8
                    s = (x+1)*8
                    value = binary[f:s]
                    container.append(int(value.bin, 2))
        return container
