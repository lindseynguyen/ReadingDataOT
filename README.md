# OTInspect (ReadingDataOT)

Công cụ kiểm kê và phân tích file trong hệ thống OT/ICS: trỏ vào một thư mục (backup trạm, project kỹ thuật, ổ chia sẻ của nhà thầu…) để biết **trong đó có gì, có những thiết bị nào, và có rủi ro cấu hình nào**.

## Tính năng (v0.2 – Giai đoạn 1)

- **Nhận dạng file OT** bằng magic bytes + nội dung + đuôi file (không cần python-magic): SCL, COMTRADE, Rockwell L5X/L5K/ACD, Siemens TIA (.apXX/.zapXX)/STEP7, Schneider, CODESYS, PLCopen XML, GSD/GSDML/EDS/ESI, OPC UA NodeSet, PCAP/PCAPNG, EVTX, firmware (HEX/SREC/BIN/ELF/SquashFS/uImage), archive.
- **IEC 61850 SCL** (SCD/ICD/CID/IID/SSD/SED), xử lý đúng namespace:
  - IED: hãng, model, configVersion, IP/subnet/gateway/MAC, LDevice, LN0/LN
  - GOOSE / SV: APPID, MAC đích, VLAN, DataSet, confRev
  - ReportControl, DataSet, VoltageLevel, Bay
- **Log / cấu hình văn bản**: đếm error/warning/alarm/auth, khoảng thời gian, IP xuất hiện nhiều nhất, phát hiện mật khẩu / SNMP community / private key dạng cleartext (được che khi hiển thị).
- **Firmware / binary**: entropy theo khối, chữ ký nhúng (SquashFS, uImage, ELF, PEM…), chuỗi đáng chú ý, dải địa chỉ Intel HEX.
- **Archive ZIP** (gồm TIA .zap): liệt kê và nhận dạng file bên trong, không giải nén ra đĩa, có chống zip bomb và path traversal.
- **Rule rủi ro**: trùng IP, trùng APPID/MAC GOOSE/SV, IP mặc định, gateway sai subnet, GOOSE không VLAN, thiếu IEC 62351-6, bí mật cleartext, firmware chứa passwd/khóa.
- **Báo cáo**: HTML (mở offline, in ra PDF từ trình duyệt), JSON, CSV (files / assets / findings).
- **GUI** PyQt5: quét trên luồng riêng (không treo), kéo-thả, 3 bảng File / Thiết bị / Phát hiện có lọc và sắp xếp, panel chi tiết.
- **CLI** cho máy air-gapped hoặc chạy định kỳ.

## Cài đặt

```bash
git clone https://github.com/lindseynguyen/ReadingDataOT.git
cd ReadingDataOT
pip install -r requirements.txt
```

Lõi và CLI chỉ cần Python 3.9+ (thư viện chuẩn). PyQt5 chỉ cần cho GUI.

## Sử dụng

```bash
# GUI
python data-kiosk.py          # hoặc: python -m otinspect gui

# CLI
python -m otinspect scan D:\Backup_TBA --html report.html --json report.json --csv out\
python -m otinspect scan ./samples --fail-on high   # exit code 2 nếu có rủi ro cao
```

Thử ngay với dữ liệu mẫu: `python -m otinspect scan samples --html demo.html`

## Kiến trúc

```
otinspect/
  core/      identify.py (nhận dạng) · scanner.py (quét, hash, song song) · registry.py · model.py
  parsers/   scl.py · logfile.py · archive.py · binary.py
  report/    export.py (HTML/JSON/CSV)
  gui/       app.py
  cli.py
```

Thêm loại file mới: tạo module trong `otinspect/parsers/` với class có `can_parse()` + `parse()`, gắn `@register`, rồi import trong `core/registry.py → load_builtin()`.

## Kiểm thử

```bash
pip install pytest && python -m pytest -q
```

## Lộ trình

- **Giai đoạn 2**: COMTRADE, PCAP (GOOSE/SV/MMS/IEC 104/Modbus/DNP3/S7), Rockwell L5X, GSDML/EDS, rule YAML.
- **Giai đoạn 3**: sơ đồ mạng từ SCL, so sánh 2 phiên bản SCD.

## Lưu ý an toàn

Công cụ chỉ **đọc** file, không kết nối tới thiết bị. Báo cáo có thể chứa IP/MAC/sơ đồ hệ thống: xử lý như tài liệu mật theo quy định nội bộ.

## License

MIT
