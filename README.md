# ARP Cache Poisoning Attack

Đồ án môn **An toàn mạng máy tính (NT101.R12)** — tìm hiểu, mô phỏng tấn công
**ARP Cache Poisoning** và **Man-in-the-Middle (MITM)**, cùng công cụ phát hiện
tấn công, dựa trên môi trường **SEED Labs 2.0**.

## Giới thiệu

Giao thức ARP không có cơ chế xác thực, nên kẻ tấn công có thể gửi gói ARP giả
để làm sai lệch bảng ánh xạ IP–MAC của nạn nhân. Khi thành công, lưu lượng mạng
bị chuyển hướng qua máy tấn công, tạo điều kiện cho tấn công MITM: nghe lén hoặc
chỉnh sửa dữ liệu. Đồ án mô phỏng toàn bộ quá trình này và xây dựng thêm một công
cụ phát hiện tấn công.

## Thông tin

- **Trường:** ĐH Công nghệ Thông tin – ĐHQG TP.HCM
- **Môn học:** An toàn mạng máy tính (NT101.R12)
- **GVHD:** ThS Lê Đức Thịnh
- **Nhóm 05:**
  - Nguyễn Nhật Thanh – 24521633
  - Trần Phú Thành – 24521641
  - Võ Diệp Thành – 24521644

## Môi trường

- Ubuntu 20.04 (VMware) + Docker, dựng theo SEED Labs 2.0
- Python 3 + Scapy, Wireshark
- Mạng Docker `10.9.0.0/24`:
  | Máy | IP | Vai trò |
  |-----|-----|---------|
  | Host A | 10.9.0.5 | Client (nạn nhân) |
  | Host B | 10.9.0.6 | Server (nạn nhân) |
  | Host M | 10.9.0.105 | Attacker (kẻ tấn công) |

## Nội dung

- **Task 1 – ARP Cache Poisoning:** đầu độc cache bằng ARP Request, ARP Reply và Gratuitous ARP.
- **Task 2 – MITM trên Telnet:** chặn và sửa dữ liệu phiên Telnet.
- **Task 3 – MITM trên Netcat:** chặn kết nối Netcat, thay thế tên và che thông tin nhạy cảm (email, số điện thoại).
- **Mở rộng – Phát hiện & Phòng chống:**
  - **ARP Spoofing Detector:** phát hiện tấn công bằng cách giám sát gói ARP, cảnh báo khi ánh xạ IP–MAC bất thường.
  - **Static ARP:** phòng chống bằng cách cố định ánh xạ IP–MAC (`arp -s`), chặn việc cache bị ghi đè.
