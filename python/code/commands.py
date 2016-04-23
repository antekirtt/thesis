#!/usr/bin/python

import readline

"""
class representing the history of commands
"""
class HistoryConsole:
    def __init__(self,history):
        self.history = history

    def complete(self,text,state):
        results =  [x+" " for x in self.history if x.startswith(text)]
        return results[state]

"""
the class manage the history of the commands
"""
class Commands:

    @classmethod
    def setMainHistory(self):
        commands = ['help', 'quit', 'testing']
        completer = HistoryConsole(commands)
        return readline.set_completer(completer.complete)                    

    @classmethod
    def setShellHistory(self):
        commands = ['help', 'quit', 'cd', 'ls', 'ls -l', 'select']
        completer = HistoryConsole(commands)
        return readline.set_completer(completer.complete)                    

    @classmethod
    def setTestingFrameworkHistory(self):
        commands = ['help', 'quit', 'covert', 'attacking']
        completer = HistoryConsole(commands)
        return readline.set_completer(completer.complete)

    
    @classmethod
    def setCovertChannelHistory(self):
        commands = ['help', 'quit', 'setEchoRequest', 'setEchoReply']
        completer = HistoryConsole(commands)
        return readline.set_completer(completer.complete)

    @classmethod
    def setAttackingChannelHistory(self):
        commands = ['help', 'quit']
        completer = HistoryConsole(commands)
        return readline.set_completer(completer.complete)
    
    @classmethod
    def setEchoRequestCovertHistory(self):
        commands = ['help', 'quit', 'code', 'identifier', 'seqNum', 'data', 'shell', 'exec', 'show', 'setAdr', 'iface', 'rec']
        completer = HistoryConsole(commands)
        return readline.set_completer(completer.complete)

"""
this is the help of the framework
"""
class Help:

    @classmethod
    def getMainHelp(self):
        return [70*'*','help \t\t\t=> Print this help', 'quit \t\t\t=> Quit framework', 40*'*', 'Modules Commands:', 'testing \t\t=> Enter the testing framework', 70*'*']

    @classmethod
    def getCovertChannelHelp(self):
        return [70*'*', 'help \t\t\t=> Print this help', 'quit \t\t\t=> Quit Covert Channel mode', 'setEchoRequest \t\t=> Set echo request covert channel mode', 'setEchoReply \t\t=> Set echo reply covert channel mode', 70*'*']

    @classmethod
    def getAttackingChannelHelp(self):
        return [70*'*', 'help \t\t\t=> Print this help', 'quit \t\t\t=> Quit Attacking Channel mode', 70*'*']

    @classmethod
    def getTestingFrameworkHelp(self):
        return [70*'*', 'help \t\t\t=> Print this help', 'quit \t\t\t=> Quit Testing Framework', 'covert \t\t\t=> Covert Channel Mode', 'attacking \t\t=> Attacking Channel Mode', 70*'*']

    @classmethod
    def getEchoRequestHelp(self):
        return [70*'*', 'help \t\t\t=>] Print this help', 'exec \t\t\t=> Module execution', 'show \t\t\t=> Show attributes', 'shell \t\t\t=> Enter in Shell mode', 'quit \t\t\t=> Quit Echo Request Covert Channel module', 40*'*', 'Modules Commands:', 'code \t\t\t=> Use code field as Covert Channel', 'identifier \t\t=> Use identifier field as Covert Channel', 'seqNum \t\t\t=> Use sequence number field as Covert Channel', 'data \t\t\t=> Use data field as Covert Channel',  40*'*', 'Shell Mode Commands:', 'quit \t\t\t=> Quit shell mode', 'ls \t\t\t=> list file and directories', 'ls -l \t\t\t=> List files and directories extended format', 'cd \t\t\t=> Change directory', 'select <file> \t\t=> select file to exfiltrate', 70*'*']

    @classmethod
    def getShellHelp(self):
        return [70*'*', 'help \t\t\t=> Print this help', 'quit \t\t\t=> Quit shell mode', 'ls \t\t\t=> list file and directories', 'ls -l \t\t\t=> List files and directories extended format', 'cd \t\t\t=> Change directory', 'select <file> \t\t=> select file to exfiltrate', 70*'*']
