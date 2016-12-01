#!/usr/bin/python

import threading
import time
from scapy.all import *


def packet_callback(packet):
        if ICMPv6ParamProblem in packet[0]:
            adr = packet[IPv6].src
            code = packet[ICMPv6ParamProblem].code
            print code
            print adr


def receiver(iface):
    sniff(iface=iface, filter='ip6', prn=packet_callback, store=0, timeout=20)


class receiverThread(threading.Thread):
    
    def __init__(self, iface):
        threading.Thread.__init__(self)
        self.iface = iface

    def run(self):
        print "Starting Receiving Packets"
        rec = receiver(self.iface)


class echoSenderThread(threading.Thread):

    def __init__(self, iface, target):
        threading.Thread.__init__(self)
        self.iface = iface
        self.target = target

    def run(self):
        print "Starting sending pongs"
        for x in range(1,100):
            p = IPv6(dst=self.target)/ICMPv6EchoReply()
            send(p, iface=self.iface, verbose=False)
            time.sleep(2)


win = "2001:abcd:acad:2:b485:2aec:9447:fd83"
linux = "2001:abcd:acad:2:a00:27ff:fe84:bb37"
allNodes = "ff02::1"
rec = receiverThread("eth0")
sendEcho = echoSenderThread("eth0", win)

rec.start()
sendEcho.start()
