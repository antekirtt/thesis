#!/usr/bin/python

import sys
import re, uuid
import os
import readline
from pprint import pprint
from commands import *
from scapy.all import *
from testingFramework import *

"""
class responsible for the testing framework
"""
class TestingFramework:

    def __init__(self, iface):
        self.name = 'Testing'
        self.iface = iface
        
    #starts the interactive propmt
    def startSystem(self):
        Commands.setTestingFrameworkHistory()
        running = 1
        while running:
            readline.parse_and_bind("tab: complete")
            #we receive data from the keyboard                    
            command  = raw_input(self.name + ' >>')
            #help command
            if re.match('help', command):
                self.showHelp()
            #quit module command
            elif re.match('quit', command):
                running = 0
                Commands.setMainHistory()
            elif re.match('covert', command):
                channel = CovertChannel(self.iface)
                channel.startSystem()                
            elif re.match('attacking', command):
                channel = AttackingChannel(self.iface)
                channel.startSystem()
            else:
                print 'Error! Command not found!'

    def showHelp(self):
        for entry in Help.getTestingFrameworkHelp():
            print entry
