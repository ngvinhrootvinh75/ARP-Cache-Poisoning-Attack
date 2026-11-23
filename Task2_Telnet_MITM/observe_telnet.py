
from scapy.all import sniff, IP, TCP, Raw

def observe(pkt):
    if IP in pkt and TCP in pkt and Raw in pkt:
        if pkt[IP].src == "10.9.0.5" and pkt[IP].dst == "10.9.0.6":
            data = bytes(pkt[Raw].load)
            print("Du lieu A -> B:", repr(data))

print("Dang quan sat luu luong Telnet...")

sniff(
    iface="eth0",
    filter="tcp port 23",
    prn=observe,
    store=False
)
