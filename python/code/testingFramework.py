#!/usr/bin/python

import sys
import re, uuid
import os
import readline
from pprint import pprint
from commands import *
from covertChannels import *
from allCovertTest import *

"""
class responsible for Covert Channel module
"""
class CovertChannel:

    def __init__(self, iface):
        self.name = 'Covert'
        self.iface = iface
        
    #starts the interactive propmt
    def startSystem(self):
        Commands.setCovertChannelHistory()
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
                Commands.setTestingFrameworkHistory()
            #set echo request covert channel
            elif re.match(r'setEchoRequest', command):
                covert = EchoRequest()
                covert.startSystem()
            #set echo reply covert channel
            elif re.match(r'setEchoReply', command):
                covert = EchoReply()
                covert.startSystem()
            #set all covert channel tests
            elif re.match(r'setAll', command):
                covert = AllTests(self.iface)
                covert.startSystem()
            else:
                print 'Error! Command not found!'

    def showHelp(self):
        for entry in Help.getCovertChannelHelp():
            print entry


"""
class responsible for Attacking Channel module
"""
class AttackingChannel:

    def __init__(self):
        self.name = 'Attacking'

    #starts the interactive propmt
    def startSystem(self):
        Commands.setAttackingChannelHistory()
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
            else:
                print 'Error! Command not found!'

    def showHelp(self):
        for entry in Help.getAttackingChannelHelp():
            print entry
