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
        if ICMPv6EchoRequest in packet[0]:
            echo =  packet[ICMPv6EchoRequest].data
            print echo

    def receive(self):
        sniff(filter='ip6', prn=self.packet_callback, store=0)
