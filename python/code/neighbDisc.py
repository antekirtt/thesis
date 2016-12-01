#!/usr/bin/python

import sys
import re, uuid
import os
import readline
from pprint import pprint
from commands import *
from RAAttacks import *
from RSAttacks import *
from NAAttacks import *
from NSAttacks import *
from redirectAttacks import *

"""
This is general class to start Neighbor Discovery protocol tests.
The linuxInterface and windwosInterface variables must be changed accordingly.
"""
class NeighborDiscoveryAttacks:

    def __init__(self, iface):
        self.iface = iface
        self.name = 'NeighborDiscovery'

    def startSystem(self):
        Commands.setNeighborDiscoveryAttacksHistory()
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
                Commands.setAttackingChannelHistory()

            #-----Router Advertisement section-----
            
            #execution of RA with Prefix internal verification
            elif re.match('execRAPrefixInternalWin', command):
                ra = RA()
                ra.execModuleInternalPrefixWin(self.iface)
            elif re.match('execRAPrefixInternalLinux', command):
                ra = RA()
                ra.execModuleInternalPrefixLinux(self.iface)
            #execution of RA with MTU internal verification
            elif re.match('execRAMTUInternalWin', command):
                ra = RA()
                ra.execModuleInternalMTUWin(self.iface)
            elif re.match('execRAMTUInternalLinux', command):
                ra = RA()
                ra.execModuleInternalMTULinux(self.iface)
            #execution of remote RA with Prefix tests    
            elif re.match('execRAPrefixRemoteWin', command):
                ra = RA()
                ra.execModuleRemotePrefixWin(self.iface)
            elif re.match('execRAPrefixRemoteLinux', command):
                ra = RA()
                ra.execModuleRemotePrefixLinux(self.iface)
            #execution of remote RA with MTU tests
            elif re.match('execRAMTURemoteWin', command):
                ra = RA()
                ra.execModuleRemoteMTUWin(self.iface)
            elif re.match('execRAMTURemoteLinux', command):
                ra = RA()
                ra.execModuleRemoteMTULinux(self.iface)

            #-----Router Solicitation section-----
            
            #execution of RS with internal verification
            elif re.match('execRSInternalWin', command):
                ra = RS()
                ra.execModuleInternalWin(self.iface)
            elif re.match('execRSInternalLinux', command):
                ra = RS()
                ra.execModuleInternalLinux(self.iface)
            elif re.match('execRSInternalFirewall', command):
                ra = RS()
                ra.execModuleInternalFirewall(self.iface)

            #-----Neighbor Advertisement section-----

            #execution of Cache Flooding with internal NAs
            elif re.match('execNACacheFloodingInternalWin', command):
                na = NA()
                na.execModuleInternalCacheFloodingWin(self.iface)
            elif re.match('execNACacheFloodingInternalLinux', command):
                na = NA()
                na.execModuleInternalCacheFloodingLinux(self.iface)
            #execution of Win Mitm with internal NAs
            elif re.match('execNAWinMitmInternal', command):
                na = NA()
                na.execModuleInternalWinMitm(self.iface)
            #execution of Cache Flooding with remote NAs to linux internal
            elif re.match('execNACacheFloodingRemoteLinux', command):
                na = NA()
                na.execModuleRemoteLinuxCacheFlooding(self.iface)
                
            #-----Neighbor Solicitation section-----
            
            #execution of NS internal test
            elif re.match('execNSInternalFloodingWin', command):
                ns = NS()
                ns.execModuleInternalCacheFloodingWin(self.iface)
            elif re.match('execNSInternalFloodingLinux', command):
                ns = NS()
                ns.execModuleInternalCacheFloodingLinux(self.iface)
            elif re.match('execNSInternalSelfSolWin', command):
                ns = NS()
                ns.execModuleInternalWinSelfSol(self.iface)
            elif re.match('execNSInternalSelfSolLinux', command):
                ns = NS()
                ns.execModuleInternalLinuxSelfSol(self.iface)
            #execution of NS external test
            elif re.match('execNSRemoteSelfSolLinux', command):
                ns = NS()
                ns.execModuleRemoteLinuxSelfSol(self.iface)

            #----Redirect section-----

            #execution of Redirect internal test
            elif re.match('execRedirectInternalWin', command):
                redirect = Redirect()
                redirect.execModuleInternalWin(self.iface)
            #execution of Redirect remote test
            elif re.match('execRedirectRemoteWin', command):
                redirect = Redirect()
                redirect.execModuleRemoteWin(self.iface)
            elif re.match('execRedirectRemoteLinux', command):
                redirect = Redirect()
                redirect.execModuleRemoteLinux(self.iface)
                
    def showHelp(self):
        for entry in Help.getNeighborDiscoveryAttacksHelp():
            print entry

