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
        commands = ['help', 'quit', 'setEchoRequest', 'setEchoReply', 'setAll']
        completer = HistoryConsole(commands)
        return readline.set_completer(completer.complete)

    @classmethod
    def setAttackingChannelHistory(self):
        commands = ['help', 'quit', 'setNeighborDiscovery', 'setInfoAndError']
        completer = HistoryConsole(commands)
        return readline.set_completer(completer.complete)
    
    @classmethod
    def setEchoRequestCovertHistory(self):
        commands = ['help', 'quit', 'code', 'identifier', 'seqNum', 'data', 'shell', 'exec', 'show', 'setAdr', 'iface', 'rec']
        completer = HistoryConsole(commands)
        return readline.set_completer(completer.complete)

    @classmethod
    def setAllCovertTestHistory(self):
        commands = ['help', 'quit', 'exec', 'rec', 'setAdr', 'frag']
        completer = HistoryConsole(commands)
        return readline.set_completer(completer.complete)

    @classmethod
    def setNeighborDiscoveryAttacksHistory(self):
        commands = ['help', 'quit', 'execRAPrefixInternalWin', 'execRAPrefixInternalLinux', 'execRAMTUInternalWin', 'execRAMTUInternalLinux', 'execRAPrefixRemoteWin', 'execRAPrefixRemoteLinux', 'execRAMTURemoteWin', 'execRAMTURemoteLinux', 'execRSInternalWin', 'execRSInternalLinux', 'execRSInternalFirewall', 'execNAWinMitmInternal', 'execNACacheFloodingInternalWin', 'execNACacheFloodingInternalLinux', 'execNACacheFloodingRemoteLinux', 'execNSInternalFloodingWin', 'execNSInternalFloodingLinux', 'execNSInternalSelfSolWin', 'execNSInternalSelfSolLinux', 'execNSRemoteSelfSolLinux', 'execRedirectInternalWin', 'execRedirectRemoteWin', 'execRedirectRemoteLinux']
        completer = HistoryConsole(commands)
        return readline.set_completer(completer.complete)

    @classmethod
    def setInfoAndErrorAttacksHistory(self):
        commands = ['help', 'quit', 'execEchoReplyRemoteWin', 'execEchoReplyRemoteLinux', 'execDestUnreachAllWin', 'execDestUnreachAllLinux', 'execDestUnreachBadCodeWin', 'execDestUnreachBadCodeLinux', 'execDestUnreachDifferentLengthLinux', 'execDestUnreachDifferentLengthWin', 'execDestUnreachNoRouteWin', 'execDestUnreachNoRouteLinux', 'execDestUnreachAdrUnreachWin','execDestUnreachAdrUnreachLinux', 'execDestUnreachPortUnreachWin', 'execDestUnreachPortUnreachLinux', 'execDestUnreachComAdminProhibWin', 'execDestUnreachComAdminProhibLinux', 'execDestUnreachBeyondScopeWin', 'execDestUnreachBeyondScopeLinux', 'execDestUnreachSrcFailedPolicyWin', 'execDestUnreachSrcFailedPolicyLinux', 'execDestUnreachRejectRouteWin', 'execDestUnreachRejectRouteLinux', 'execPacketTooBigMTUBigWin', 'execPacketTooBigMTUBigLinux', 'execPacketTooBigMTUSmallWin', 'execPacketTooBigMTUSmallLinux', 'execPacketTooBigMTUWin', 'execPacketTooBigMTULinux', 'execPacketTooBigBadCodeWin', 'execPacketTooBigBadCodeLinux', 'execTimeExceededBadCodeWin', 'execTimeExceededBadCodeLinux', 'execTimeExceededHopLimitWin', 'execTimeExceededHopLimitLinux', 'execTimeExceededFragmentReassemblyWin', 'execTimeExceededFragmentReassemblyLinux', 'execTimeExceededLengthWin', 'execTimeExceededLengthLinux', 'execParameterProblemBadCodeWin', 'execParameterProblemBadCodeLinux', 'execParameterProblemFloodPointerWin', 'execParameterProblemFloodPointerLinux', 'execParameterProblemFloodHighPointerWin', 'execParameterProblemFloodHighPointerLinux', 'execParameterProblemErrHeaderWin', 'execParameterProblemErrHeaderLinux', 'execParameterProblemUnrecHeaderWin', 'execParameterProblemUnrecHeaderLinux', 'execParameterProblemUnrecIPOptionWin', 'execParameterProblemUnrecIPOptionLinux', 'execEchoRequestNeighCacheExhaustionDstVictimWin', 'execEchoRequestNeighCacheExhaustionDstVictimLinux', 'execEchoRequestNeighCacheExhaustionSrcVictimWin', 'execEchoRequestNeighCacheExhaustionSrcVictimLinux']
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
        return [70*'*', 'help \t\t\t=> Print this help', 'quit \t\t\t=> Quit Covert Channel mode', 'setEchoRequest \t\t=> Set echo request covert channel mode', 'setEchoReply \t\t=> Set echo reply covert channel mode', 'setAll \t\t\t=> Set all covert channels testing mode',70*'*']

    @classmethod
    def getAttackingChannelHelp(self):
        return [70*'*', 'help \t\t\t=> Print this help', 'quit \t\t\t=> Quit Attacking Channel mode', 'setNeighborDiscovery \t=> Set NeighborDiscovery attacks', 'setInfoAndError \t=> Set Info and Error attacks', 70*'*']

    @classmethod
    def getTestingFrameworkHelp(self):
        return [70*'*', 'help \t\t\t=> Print this help', 'quit \t\t\t=> Quit Testing Framework', 'covert \t\t\t=> Covert Channel Mode', 'attacking \t\t=> Attacking Channel Mode', 70*'*']

    @classmethod
    def getEchoRequestHelp(self):
        return [70*'*', 'help \t\t\t=>] Print this help', 'exec \t\t\t=> Module execution', 'show \t\t\t=> Show attributes', 'shell \t\t\t=> Enter in Shell mode', 'quit \t\t\t=> Quit Echo Request Covert Channel module', 40*'*', 'Modules Commands:', 'code \t\t\t=> Use code field as Covert Channel', 'identifier \t\t=> Use identifier field as Covert Channel', 'seqNum \t\t\t=> Use sequence number field as Covert Channel', 'data \t\t\t=> Use data field as Covert Channel',  40*'*', 'Shell Mode Commands:', 'quit \t\t\t=> Quit shell mode', 'ls \t\t\t=> list file and directories', 'ls -l \t\t\t=> List files and directories extended format', 'cd \t\t\t=> Change directory', 'select <file> \t\t=> select file to exfiltrate', 70*'*']

    @classmethod
    def getShellHelp(self):
        return [70*'*', 'help \t\t\t=> Print this help', 'quit \t\t\t=> Quit shell mode', 'ls \t\t\t=> list file and directories', 'ls -l \t\t\t=> List files and directories extended format', 'cd \t\t\t=> Change directory', 'select <file> \t\t=> select file to exfiltrate', 70*'*']

    @classmethod
    def getAllCovertTestHelp(self):
        return [70*'*', 'help \t\t\t=> Print this help', 'quit \t\t\t=> Quit all covert channels test mode', 'setAdr \t\t\t=> Set the IPv6 address both to send and to receive', 'frag \t\t\t=> Toggle packet fragmentation', 'exec \t\t\t=> Start all covert channels test', 'rec \t\t\t=> Start the receiver for the tests', 70*'*']

    @classmethod
    def getNeighborDiscoveryAttacksHelp(self):
        return [70*'*', 'help \t\t\t=> Print this help', 'quit \t\t\t=> Quit Neighbor Discovery attacking test mode', 'setAdr \t\t\t=> Set the IPv6 address to attack', 25*'*', 'execRAPrefixRemote \t=> Start RA with Prefix option attacking test', 'execRAPrefixInternal \t=> Start RA with Prefix internal verification test', 'execRAMTURemote \t=> Start RA with MTU option attacking test', 'execRAMTUInternal \t=> Start RA with MTU internal verification test', 25*'*','execNAWinMitmInternal \t=> Start Mitm against Win device from Internal Debian','execNACacheFloodingInternal \t=> Start Neighbor cache flooding against address', 'execNARemote \t\t=> Start NA attacking test', 25*'*', 'execNSInternal \t\t=> Start NS internal verification test', 'execNSRemote \t\t=> Start NS attacking test', 25*'*', 'execRedirectInternal \t=> Start redirect internal verification test', 'execRedirectRemote \t=> Start redirect attacking test', 70*'*']

    @classmethod
    def getInfoAndErrorAttacksHelp(self):
        return [70*'*', 'help \t\t\t=> Print this help', 'quit \t\t\t=> Quit Info and Error attacking test mode', 'setAdr \t\t\t=> Set the IPv6 address to attack', 25*'*', 'execEchoReplyRemote \t=> Start Echo Reply attacking test', 70*'*']
