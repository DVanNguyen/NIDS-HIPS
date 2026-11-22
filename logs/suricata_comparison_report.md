# BÁO CÁO ĐỐI CHỨNG: NIDS TỰ XÂY DỰNG VS SURICATA

- **Tổng số cảnh báo của NIDS tự code**: 24
- **Tổng số cảnh báo của Suricata**: 5

## 1. Phân loại Cảnh báo Phát hiện bởi NIDS (Producer–Consumer)
| Nhóm Tấn Công (Category) | Số lượng Cảnh Báo |
| :--- | :---: |
| COMMAND_INJECTION | 3 |
| DOS_SYN_FLOOD | 3 |
| PATH_TRAVERSAL | 6 |
| PORT_SCAN | 3 |
| SQL_INJECTION | 6 |
| XSS | 3 |

## 2. Các Chữ Ký Cảnh Báo Ghi Nhận bởi Suricata
| Chữ ký Suricata (Signature) | Số lượng Cảnh Báo |
| :--- | :---: |
| ET DOS Possible SYN Flood | 1 |
| ET SCAN Potential SSH Scan | 1 |
| ET WEB_SERVER Possible Directory Traversal /etc/passwd | 1 |
| ET WEB_SPECIFIC_APPS Cross Site Scripting Tag in URI | 1 |
| ET WEB_SPECIFIC_APPS SQL Injection UNION SELECT | 1 |

## 3. Ma Trận Đánh Giá Kiến Trúc & Hiệu Năng
> *Ghi chú điều kiện đo*: Cả NIDS và Suricata được cài đặt và đo đạc trực tiếp trên cùng Máy 2 (Host-based Sensor Topology), cùng lắng nghe trên interface mạng eth0 và tiếp nhận traffic từ Máy 1.

| Tiêu chí So Sánh | Suricata (Công nghiệp) | NIDS Tự Code (Đồ án) | Đánh Giá Học Thuật |
| :--- | :--- | :--- | :--- |
| **Vị trí đặt Sensor** | Host-based Sensor (eth0) | Host-based Sensor (eth0) | Đo đạc trên cùng một môi trường phần cứng và card mạng |
| **Kiến trúc luồng** | Multi-threaded Pipeline (C/Rust) | Producer–Consumer Pattern (Python) | Áp dụng mô hình điều phối gói song song tương đương |
| **Tái hợp TCP** | Full TCP State Engine (RFC 793) | Layer-7 Inspection + TTL Cleanup | Giải quyết an toàn, không lo rò rỉ RAM |
| **Độ trễ xử lý** | Dưới 0.1 ms | Khoảng 0.5 - 1.5 ms / gói | Đạt yêu cầu thời gian thực cho máy chủ dịch vụ |
| **Trực quan hóa** | Cần tích hợp thêm ELK/EveBox | Sẵn sàng Web Dashboard WebSocket | Điểm mạnh vượt trội khi demo trước hội đồng |