#!/usr/bin/env python3
import sys
import argparse
from datetime import datetime

try:
    from scapy.all import sniff, ARP, get_if_hwaddr
except ImportError:
    print("Thieu thu vien scapy. Cai bang: pip3 install scapy")
    sys.exit(1)

BASELINE = {
    "10.9.0.5": "02:42:0a:09:00:05",
    "10.9.0.6": "02:42:0a:09:00:06",
}

ip_to_mac = dict(BASELINE)
mac_to_ips = {}
alerted = set()

LOG_FILE = "arp_alerts.log"

RED, YLW, GRN, CYN, RST = "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[0m"


def stamp():
    return datetime.now().strftime("%H:%M:%S")


def log_line(text):
    print(text)
    clean = text
    for c in (RED, YLW, GRN, CYN, RST):
        clean = clean.replace(c, "")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(clean + "\n")
    except OSError:
        pass


def alert(key, text):
    if key in alerted:
        return
    alerted.add(key)
    log_line(f"{RED}[{stamp()}] [CANH BAO] {text}{RST}")


def handle(pkt):
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]
    op = arp.op
    ip = arp.psrc
    mac = arp.hwsrc
    pdst = arp.pdst

    if not ip or not mac or mac == "00:00:00:00:00:00":
        return

    kind = "REPLY" if op == 2 else "REQUEST"

    if ip == pdst:
        log_line(f"{YLW}[{stamp()}] [LUU Y] Gratuitous ARP: {ip} tu quang ba "
                 f"MAC {mac} ({kind}){RST}")

    if ip in ip_to_mac:
        if ip_to_mac[ip] != mac:
            alert(f"A:{ip}:{mac}",
                  f"IP {ip} doi MAC: {ip_to_mac[ip]} -> {mac}  "
                  f"(goi {kind}). Nghi bi dau doc ARP!")
            ip_to_mac[ip] = mac
    else:
        ip_to_mac[ip] = mac
        log_line(f"{CYN}[{stamp()}] [HOC] Ghi nhan {ip} -> {mac}{RST}")

    mac_to_ips.setdefault(mac, set()).add(ip)
    if len(mac_to_ips[mac]) > 1:
        ips = ", ".join(sorted(mac_to_ips[mac]))
        alert(f"B:{mac}:{ips}",
              f"MAC {mac} dang nhan nhieu IP: [{ips}]  -> NGHI MITM!")


def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Detector")
    parser.add_argument("-i", "--iface", default="eth0",
                        help="Interface de giam sat (mac dinh: eth0)")
    args = parser.parse_args()

    log_line(f"{GRN} ARP Spoofing Detector - dang giam sat tren {args.iface}{RST}")
    log_line(f"{GRN} Baseline tin cay:{RST}")
    for k, v in BASELINE.items():
        log_line(f"{GRN}   {k} -> {v}{RST}")
    log_line(f"{GRN} Nhan Ctrl+C de dung. Log luu vao: {LOG_FILE}{RST}")

    try:
        sniff(iface=args.iface, filter="arp", prn=handle, store=False)
    except PermissionError:
        print("Can quyen root. Chay lai voi: sudo python3 arp_detector.py")
    except OSError as e:
        print(f"Loi mo interface '{args.iface}': {e}")
        print("Kiem tra ten interface bang lenh: ip link")
    except KeyboardInterrupt:
        pass
    finally:
        log_line(f"{GRN}[{stamp()}] Da dung Detector.{RST}")


if __name__ == "__main__":
    main()

