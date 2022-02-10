#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time

import select   #additional needed import


def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))


class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        timeLeft = timeout
        while True: #while waiting for packet
            selectStart = time.time()   #start time
            inputReady = select.select([icmpSocket], [], [], timeLeft)  #putting the time left into the equation
            selectTime = (time.time() - selectStart) #after the time left, we get the overall time minus the start time

        # 2. Once received, record time of receipt, otherwise, handle a timeout
            
            if inputReady[0] == []:
                return "Timeout"

            timeReceived = time.time()
            #print(timeReceived)
            recordReceipt, address = icmpSocket.recvfrom(1024)

        # 3. Compare the time of receipt to time of sending, producing the total network delay
        # 4. Unpack the packet header for useful information, including the ID
            icmpHeader = recordReceipt[20:28]
            icmpType, icmpCode, icmpChecksum, icmpId, icmpSequence = struct.unpack("bbHHh", icmpHeader)

        # 5. Check that the ID matches between the request and reply
        # 6. Return total network delay
            if type != 8 and icmpId == ID:
                #bytesDouble = struct.calcsize("d")
                #timeSent = struct.unpack("d", recordReceipt[28:28 + bytesDouble])[0]
                #networkDelay = timeReceived - timeSent
                return timeReceived


            timeLeft -= selectTime
            if timeLeft <= 0:
                return "Timeout"

        pass

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        destinationAddress = socket.gethostbyname(destinationAddress)
        checksumICMP = 0

        header = struct.pack("bbHHh", 8, 0, checksumICMP, ID, 1)
        data = struct.pack("d", time.time())

        # 2. Checksum ICMP packet using given function
        checksumICMP = self.checksum(header+data)

        # 3. Insert checksum into packet
        header = struct.pack("bbHHh", 8, 0, checksumICMP, ID, 1)
        packet = header + data

        # 4. Send packet using socket
        icmpSocket.sendto(packet, (destinationAddress,1))

        # 5. Record time of sending
        timeSent = time.time()
        #print(timeSent)
        return timeSent
        pass

    def doOnePing(self, destinationAddress, timeout):
        # 1. Create ICMP socket
        icmp = socket.getprotobyname("icmp")
        icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        # 2. Call sendOnePing function
        ID = os.getpid() & 0xffff #get the process ID of the current process
        timeSent = self.sendOnePing(icmpSocket, destinationAddress, ID)
        # 3. Call receiveOnePing function
        timeReceived = self.receiveOnePing(icmpSocket, destinationAddress, ID, timeout)
        # 4. Close ICMP socket
        icmpSocket.close()
        # 5. Return total network delay
        delay = timeReceived - timeSent
        delay = delay * 1000
        #print(delay)
        return delay
        pass

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        destAddr = socket.gethostbyname(args.hostname)
        # 2. Call doOnePing function, approximately every second
        while True:
            delay = self.doOnePing(destAddr, 1)
            time.sleep(1)
        # 3. Print out the returned delay (and other relevant details) using the printOneResult method
            self.printOneResult(args.hostname, 50, delay, 60)
        
        # 4. Continue this process until stopped


class Traceroute(NetworkApplication): # provides a map of how data on the internet travels from its source to its destination. 

    # A traceroute works by sending Internet Control Message Protocol (ICMP) packets, 
    # and every router involved in transferring the data gets these packets. 
    # The ICMP packets provide information about whether the routers used in the transmission are able to effectively transfer the data.

    # Our receive function with which we catch the signal
    def receiveIP(destAddr, icmpSocket, timeout):

        timeLeft = timeout

        while True: #while waiting for packet
            #selectStart = time.time()   #start time
            #selectedTime = (time.time() - selectStart) #after the time left, we get the overall time minus the start time

            inputReady = select.select([icmpSocket], [], [], timeLeft)  #putting the time left into the equation

            if inputReady[0] == []:
                return "Timeout"
            else:
                recordReceipt, address = icmpSocket.recvfrom(1024)

                if address[0] == destAddr:
                    icmpSocket.close()
                    return address[0], True
                else:
                    icmpSocket.close()
                    return address[0], True

        pass

    # This is the thing that we send along the traceroute
    def createHeader(self): 
        
        # 1. Just like in our sendPing, we create a packet with a header
        checksumTrc = 0
        ID = os.getpid() & 0xFFFF   #get the process ID of the current process

        header = struct.pack("bbHHh", 8, 0, checksumTrc, ID, 1)
        data = struct.pack("d", time.time())

        # 2. Checksum Traceroute packet using given function
        checksumTrc = self.checksum(header+data)

        # 3. Insert checksum into packet
        header = struct.pack("bbHHh", 8, 0, checksumTrc, ID, 1)
        packet = header + data
        
        # 4. Return packet
        return packet

    # This is the route that we send the packet to
    def createRoute(targetIP, timeout):
        timeLeft = timeout

        ipTTL = 1 #initiliase the ttl at 1 for the start
        tempIP = '' #store all the ips we pass through
        destAddr = socket.gethostbyname(targetIP) #get the destination address from the traceroute command

        while tempIP != destAddr and ipTTL <= 32: #until the temp address and the dest address match and there are no more than 32 hops, loop
            
            #Getting the sockets ready
            #Using the ICMP instead of the UDP, so we force the traceroute to do that
            icmp = socket.getprotobyname("icmp")
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            icmpSocket.setsockopt(socket.IPPROTO_TCP, socket.IP_TTL, struct.pack('I', ipTTL)) #'I' command for ICMP
            icmpSocket.settimeout(timeLeft)

            startTime = time.time()
            d = self.createHeader()

         




    def __init__(self, args):

        # 1. Please ensure you print each result using the printOneResult method!
        print('Traceroute to: %s...' % (args.hostname))

        # 2. Look up hostname, resolving it to an IP address
        target_ip = socket.gethostbyname(args.hostname)

        # 3. Call doOnePing function, approximately every second
        while True:
            #call get route
            time.sleep(1)



class WebServer(NetworkApplication):

    def handleRequest(tcpSocket):
        # 1. Receive request message from the client on connection socket
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        # 7. Close the connection socket
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        # 2. Bind the server socket to server address and server port
        # 3. Continuously listen for connections to server socket
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        # 5. Close server socket


class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
