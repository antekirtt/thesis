#!/usr/bin/python

import sys
import re, uuid
import os
import readline
from pprint import pprint
from commands import *
from covertChannels import *
from allCovertTest import *
from allAttackingTest import *
from neighbDisc import *
from infoAndErrorAttacks import *

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
            #set all covert channel tests
            elif re.match(r'setAll', command):
                covert = AllCovertTests(self.iface)
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

    def __init__(self, iface):
        self.name = 'Attacking'
        self.iface = iface

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
            #set all Neighbor Discovery tests
            elif re.match(r'setNeighborDiscovery', command):
                neighDisc = NeighborDiscoveryAttacks(self.iface)
                neighDisc.startSystem()
            #set all Informational and Error tests
            elif re.match(r'setInfoAndError', command):
                infoError = InfoAndErrorAttacks(self.iface)
                infoError.startSystem()
            else:
                print 'Error! Command not found!'

    def showHelp(self):
        for entry in Help.getAttackingChannelHelp():
            print entry
