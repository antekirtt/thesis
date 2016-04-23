#!/usr/bin/python

import optparse
import sys
import re, uuid
import os
import readline
from pprint import pprint
from commands import *
from modules import *

"""
class responsible for framework initialization
it shows a command prompt, has tab completion and history of commands
"""
class ICMPv6:

    def __init__(self):
        self.commandBuffer = []

    #shows the logo of the framework
    def startupLogo(self):
        initLogo = [80*'*', '', '\t\t\tICMPv6 abusing - Proof of Concept', '', 80*'*']
        for line in initLogo:
            print line

    #starts the interactive prompt
    def startSystem(self):
        self.startupLogo()
        Commands.setMainHistory()
        running = 1
        while running:
            readline.parse_and_bind("tab: complete")
            #we receive data from the keyboard                    
            command  = raw_input('[]>')
            #commands
            if re.match('help', command):
                self.showHelp()
            elif re.match('quit', command):
                running = 0
                sys.exit(1)
            elif re.match(r'testing', command):
                module = TestingFramework()
                module.startSystem()
            else:
                print 'Error! Command not found!'
    
    def showHelp(self):
        for entry in Help.getMainHelp():
            print entry

def main():
    parser = optparse.OptionParser("usage: %prog")
    (options, args) = parser.parse_args()
    icmpv6 = ICMPv6()
    icmpv6.startSystem()
    
if __name__ == '__main__':
	main()
