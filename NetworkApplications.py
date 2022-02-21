#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
from audioop import add
import socket
import os
import sys
import struct
import time

import select   #additional needed import
import threading #additional for proxy and additional task web server


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

    #def printTraceroute (self, ttl: int, destinationAddress: str, time1: float, time2: float, time3: float):
         #print("%d , %s , %.2f , %.2f , %.2f" % (ttl, destinationAddress, time1, time2, time3))

class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinAddress, ID, timeout):
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
        # 6. Return time received
            if type != 8 and icmpId == ID:
                return timeReceived


            timeLeft -= selectTime
            if timeLeft <= 0:
                return "Timeout"

        pass

    def sendOnePing(self, icmpSocket, destinAddress, ID):
        # 1. Build ICMP header
        destinAddress = socket.gethostbyname(destinAddress)
        checksumICMP = 0

        header = struct.pack("bbHHh", 8, 0, checksumICMP, ID, 1)
        data = struct.pack("d", time.time())

        # 2. Checksum ICMP packet using given function
        checksumICMP = self.checksum(header+data)

        # 3. Insert checksum into packet
        header = struct.pack("bbHHh", 8, 0, checksumICMP, ID, 1)
        packet = header + data

        # 4. Send packet using socket
        icmpSocket.sendto(packet, (destinAddress,1))

        # 5. Record time of sending
        timeSent = time.time()
        #print(timeSent)
        return timeSent
        pass

    def doOnePing(self, destinAddress, timeout):
        # 1. Create ICMP socket
        icmp = socket.getprotobyname("icmp")
        icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

        # 2. Call sendOnePing function
        ID = os.getpid() & 0xffff #get the process ID of the current process
        timeSent = self.sendOnePing(icmpSocket, destinAddress, ID)

        # 3. Call receiveOnePing function
        timeReceived = self.receiveOnePing(icmpSocket, destinAddress, ID, timeout)

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


class Traceroute(NetworkApplication): # provides a map of how data on the internet travels from its source to its destination. 

    # A traceroute works by sending Internet Control Message Protocol (ICMP) packets, 
    # and every router involved in transferring the data gets these packets. 
    # The ICMP packets provide information about whether the routers used in the transmission are able to effectively transfer the data.

    # Our receive function with which we catch the signal, following the structure of the receiveOnePing method
    def receiveIP(self, destAddr, icmpSocket, timeout):

        timeLeft = timeout

        while True: #while waiting for packet

            #selectStart = time.time()   #start time
            inputReady = select.select([icmpSocket], [], [], timeLeft)  #putting the time left into the equation
            #selectedTime = (time.time() - selectStart) #after the time left, we get the overall time minus the start time

            if inputReady[0] == []:
                return "Timeout", False
            else:
                recordReceipt, address = icmpSocket.recvfrom(1024)
                icmpSocket.close()
                return address[0], True


    # This is the thing that we send along the traceroute, following the structure of the sendOnePing method
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
    def createRoute(self, targetIP, timeout):
        timeLeft = timeout

        ipTTL = 1 #initiliase the ttl at 1 for the start
        tempIP = '' #store all the ips we pass through
        destAddr = socket.gethostbyname(targetIP) #get the destination address from the traceroute command
        #print(destAddr)

        #while tempIP != destAddr and ipTTL <= 32: #until the temp address and the dest address match and there are no more than 32 hops, loop
        for ipTTL in range(1, 32):
            #print(tempIP)
            multipleDelays = [] #for the multiple delays as in the unix command traceroute

            for i in range(3):
                #Getting the sockets ready
                #Using the ICMP instead of the UDP, so we force the traceroute to do that
                icmp = socket.getprotobyname("icmp")
                icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
                icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ipTTL) #'I' command for ICMP
                icmpSocket.settimeout(timeLeft)

                startTime = time.time() #start timer
                d = self.createHeader() #calling our header method, which gives us everything for sending signal

                icmpSocket.sendto(d, (destAddr, 0)) #sending packet
                tempIP, trcBoolean = self.receiveIP(destAddr,icmpSocket, 1) #calling receiving function and receiving the destination address
                receiveTime = time.time() #received timer

                if trcBoolean: #checking for delays
                    answer = receiveTime - startTime
                    answer = answer * 1000
                    multipleDelays.append( #appending
                        str(round(answer, 2)))
                elif trcBoolean is False:
                    multipleDelays.append('*')

            if trcBoolean: #checking again
                if destAddr == tempIP:
                    print(ipTTL, tempIP, multipleDelays[0], multipleDelays[1], multipleDelays[2])
                    print("FOUND ADDRESS")
                    icmpSocket.close()
                    break
                elif ipTTL > 32:
                    print(ipTTL, tempIP, multipleDelays[0], multipleDelays[1], multipleDelays[2])
                    icmpSocket.close()
                    break
                else:
                    print(ipTTL, tempIP , multipleDelays[0], multipleDelays[1], multipleDelays[2])
            elif trcBoolean is False:
                if ipTTL < 32:
                    print(ipTTL, tempIP, multipleDelays[0], multipleDelays[1], multipleDelays[2])
                elif ipTTL >= 32:
                    print(ipTTL, tempIP, multipleDelays[0], multipleDelays[1], multipleDelays[2])
                    icmpSocket.close()
                    break
                
            ipTTL = ipTTL + 1 #incrementing ttl with 1

         
    def __init__(self, args):
        print('Tracerouting to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        destAddr = socket.gethostbyname(args.hostname)

        # 2. Call createRoute function, approximately every second
        self.createRoute(destAddr, 1)
        time.sleep(1)


class WebServer(NetworkApplication):

    def handleRequest(self, tcpSocket):
        try:
            # 1. Receive request message from the client on connection socket
            reqMessage = tcpSocket.recv(1024)

            # 2. Extract the path of the requested object from the message (second part of the HTTP header)
            #print(reqMessage)
            reqMessage = reqMessage.decode('utf-8')
            file = reqMessage.split()[1]

            #print(reqMessage)
            # 3. Read the corresponding file from disk
            # 4. Store in temporary buffer
            fileOpen = open(file[1:])
            readingFile = fileOpen.read()

            # 5. Send the correct HTTP response error
            tcpSocket.send(bytes("HTTP/1.1 200 OK\r\n\r\n","utf-8"))

            # 6. Send the content of the file to the socket
            tcpSocket.send(bytes(readingFile, "utf-8"))
            fileOpen.close()

            # 7. Close the connection socket
            tcpSocket.close()
        
        except IOError:
            pass
            tcpSocket.send(bytes("HTTP/1.1 404 Not Found \r\n\r\n","utf-8"))
            print("Error 404: FILE NOT FOUND")

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        serverPort = args.port
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 2. Bind the server socket to server address and server port
        serverSocket.bind(("127.0.0.1", serverPort))

        # 3. Continuously listen for connections to server socket
        serverSocket.listen(1)

        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        while True:
            print("Ready to listen:")
            connectionSocket, addr = serverSocket.accept()
            self.handleRequest(connectionSocket)

        # 5. Close server socket
        serverSocket.close()


class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))
        # 1. Create server socket
        serverPort = args.port
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # making the socket reusable

        # 2. Bind the server socket to server address and server port
        serverSocket.bind(("127.0.0.1", serverPort))

        # 3. Continuously listen for connections to server socket
        serverSocket.listen(1)

        # 4. When a connection is accepted, call handleProxy function, creating our Web Proxy 
        while True:
            print("Ready to listen:")
            connectionSocket, connectionAddr = serverSocket.accept() # accepting connections

            thread = threading.Thread(target=self.handleProxy, args=(connectionSocket, connectionAddr)) # making the threads and initiating the proxy
            thread.setDaemon(True)
            thread.start()
        # 5. Close server socket
        serverSocket.close()

    def handleProxy(self, tcpSocket, tcpAddress):

        # 1. Receive request message from the client on connection socket
        reqMessage = tcpSocket.recv(10000)
        reqMessage = reqMessage.decode('utf-8')
        #print(reqMessage)

        # 2. Extracting the needed things of the requested object from the message - read the text, create a url, read file whenever there is one 
        type = reqMessage.split('\n')[0] #first line
        host = reqMessage.split()[4].split(':')[0]
        tcpAddress = socket.gethostbyname(host) #get the target address

        #print(type)
        #print(host)
        #print(tcpAddress)
        

        # 3. Handle web server and send packet
        # except FileNotFoundError , if no file found, write on file
        try:
            reply = b''
            port = 80
            newSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            newSocket.connect((tcpAddress, port))
            newSocket.send(bytes(reqMessage, "utf-8"))

            while True:
                selectingSocket = select.select([newSocket],[],[],1) #if timeout 3 empty parameters appear
                if selectingSocket[0]: #check if there is a timeout
                    receiveMessage = newSocket.recv(10000)
                    reply += receiveMessage
                else:
                    break
                #print(receiveMessage)

            if(len(reply) > 0): #putting boundaries on the receive message
                tcpSocket.sendall(reply)
            else: 
                return 

        except socket.error:
            if newSocket:
                newSocket.close()
            if tcpSocket:
                tcpSocket.close()

            sys.exit(1)

        # Final step. Close the socket
        newSocket.close()
        tcpSocket.close()


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
