from PyQt5 import QtWidgets
import sys
import os
import magic
import xml.etree.ElementTree as ET
from fpdf import FPDF
import webbrowser
import struct


class OTFileAnalyzer(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle('OT File Analyzer')
        self.setGeometry(200, 200, 1200, 800)

        # Chọn file hoặc thư mục
        self.path_label = QtWidgets.QLabel('Chọn File/Thư Mục:', self)
        self.path_label.setGeometry(20, 20, 150, 30)
        self.path_input = QtWidgets.QLineEdit(self)
        self.path_input.setGeometry(180, 20, 800, 30)
        self.browse_button = QtWidgets.QPushButton('Browse', self)
        self.browse_button.setGeometry(1000, 20, 100, 30)
        self.browse_button.clicked.connect(self.browse_path)

        # Metadata
        self.metadata_label = QtWidgets.QLabel('Metadata:', self)
        self.metadata_label.setGeometry(20, 70, 150, 30)
        self.metadata_display = QtWidgets.QTextBrowser(self)
        self.metadata_display.setGeometry(20, 110, 1140, 200)

        # Kết quả phân tích
        self.result_label = QtWidgets.QLabel('Kết quả Phân Tích:', self)
        self.result_label.setGeometry(20, 330, 200, 30)
        self.result_display = QtWidgets.QTextBrowser(self)
        self.result_display.setGeometry(20, 370, 1140, 300)

        # Các nút chức năng
        self.analyze_file_button = QtWidgets.QPushButton('Phân Tích File', self)
        self.analyze_file_button.setGeometry(20, 700, 150, 40)
        self.analyze_file_button.clicked.connect(self.analyze_file)

        self.analyze_dir_button = QtWidgets.QPushButton('Phân Tích Thư Mục', self)
        self.analyze_dir_button.setGeometry(200, 700, 150, 40)
        self.analyze_dir_button.clicked.connect(self.analyze_directory)

        self.export_button = QtWidgets.QPushButton('Xuất Báo Cáo', self)
        self.export_button.setGeometry(380, 700, 150, 40)
        self.export_button.clicked.connect(self.export_report)

        self.reference_button = QtWidgets.QPushButton('Tham Khảo Nguồn', self)
        self.reference_button.setGeometry(560, 700, 150, 40)
        self.reference_button.clicked.connect(self.open_references)

        self.quit_button = QtWidgets.QPushButton('Thoát', self)
        self.quit_button.setGeometry(740, 700, 150, 40)
        self.quit_button.clicked.connect(self.close)

        self.show()
    
    def browse_path(self):
        options = QtWidgets.QFileDialog.Options()
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Chọn Thư Mục", options=options)
        if path:
            self.path_input.setText(path)
            self.display_metadata(path)

    def display_metadata(self, path):
        if os.path.isdir(path):
            file_count = len(os.listdir(path))
            metadata = f"Đã chọn thư mục: {path}\nSố lượng file: {file_count}"
        elif os.path.isfile(path):
            file_type = magic.Magic(mime=True).from_file(path)
            file_size = os.path.getsize(path)
            metadata = f"File Path: {path}\nFile Type: {file_type}\nFile Size: {file_size} bytes"
        else:
            metadata = "Đường dẫn không hợp lệ!"
        self.metadata_display.setText(metadata)

    def analyze_file(self):
        path = self.path_input.text()
        if not os.path.isfile(path):
            self.result_display.setText("Vui lòng chọn một file hợp lệ để phân tích!")
            return

        file_type = magic.Magic(mime=True).from_file(path)
        self.result_display.append(f"Đang phân tích file loại: {file_type}")

        if "xml" in file_type:
            self.result_display.append("Phân tích file XML (SCL)...")
            analysis = self.analyze_scl(path)
            if "error" in analysis:
                self.result_display.append(analysis["error"])
            else:
                self.result_display.append(f"Logical Devices: {analysis['Logical Devices']}")
                self.result_display.append(f"Logical Nodes: {analysis['Logical Nodes']}")
                self.result_display.append(f"GOOSE Messages: {analysis['GOOSE Messages']}")

        elif "text" in file_type:
            self.result_display.append("Phân tích file nhật ký...")
            analysis = self.analyze_log(path)
            if "error" in analysis:
                self.result_display.append(analysis["error"])
            else:
                self.result_display.append(f"Lỗi: {analysis['Errors']}")
                self.result_display.append(f"Cảnh báo: {analysis['Warnings']}")

        elif "binary" in file_type or "octet-stream" in file_type:
            self.result_display.append("Phân tích file nhị phân...")
            analysis = self.analyze_binary(path)
            if "error" in analysis:
                self.result_display.append(analysis["error"])
            else:
                self.result_display.append(f"Header: {analysis['Header']}")
                self.result_display.append(f"Metadata: {analysis['Metadata']}")

        else:
            self.result_display.append("Loại file không được hỗ trợ.")

    def analyze_directory(self):
        path = self.path_input.text()
        if not os.path.isdir(path):
            self.result_display.setText("Vui lòng chọn một thư mục hợp lệ để phân tích!")
            return

        # Tạo nhóm kết quả
        results = {
            "XML": [],
            "Log": [],
            "Binary": [],
            "Unknown": [],
        }

        self.result_display.setText(f"Đang phân tích thư mục: {path}\n")

        for file_name in os.listdir(path):
            file_path = os.path.join(path, file_name)
            if os.path.isfile(file_path):
                file_type = magic.Magic(mime=True).from_file(file_path)

                if "xml" in file_type:
                    if self.is_scl_file(file_path):
                        results["XML"].append((file_name, "Cấu hình SCL hợp lệ (IEC 61850)"))
                    else:
                        results["XML"].append((file_name, "File XML không phải SCL"))
                elif "text" in file_type:
                    if self.contains_keywords(file_path, ["error", "warning", "timeout"]):
                        results["Log"].append((file_name, "File nhật ký có lỗi hoặc cảnh báo"))
                    else:
                        results["Log"].append((file_name, "File nhật ký (Log File)"))
                elif "binary" in file_type or "octet-stream" in file_type:
                    results["Binary"].append((file_name, "File nhị phân (Binary)"))
                else:
                    results["Unknown"].append((file_name, "Không xác định được loại file"))

        # Hiển thị kết quả theo nhóm
        for group, files in results.items():
            self.result_display.append(f"\n--- {group} ---")
            for file_name, info in files:
                self.result_display.append(f"Phân tích file: {file_name} -> {info}")

        # Hiển thị thống kê cuối cùng
        self.result_display.append("\n--- Thống kê ---")
        for group, files in results.items():
            self.result_display.append(f"{group}: {len(files)} file(s)")

    def is_scl_file(self, file_path):
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            return any(tag in root.tag.lower() for tag in ["scl", "lnode", "gsecontrol"])
        except ET.ParseError:
            return False

    def contains_keywords(self, file_path, keywords):
        try:
            with open(file_path, "r") as file:
                content = file.read().lower()
                return any(keyword in content for keyword in keywords)
        except Exception:
            return False

    def analyze_scl(self, file_path):
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            analysis = {"Logical Devices": [], "Logical Nodes": [], "GOOSE Messages": []}
            for ld in root.findall(".//LDevice"):
                analysis["Logical Devices"].append(ld.attrib.get("inst"))
            for lnode in root.findall(".//LNode"):
                analysis["Logical Nodes"].append(lnode.attrib)
            for goose in root.findall(".//GSEControl"):
                analysis["GOOSE Messages"].append(goose.attrib)
            return analysis
        except Exception as e:
            return {"error": f"Lỗi phân tích SCL: {e}"}

    def analyze_log(self, file_path):
        try:
            analysis = {"Errors": [], "Warnings": []}
            with open(file_path, "r") as log_file:
                for line in log_file:
                    if "error" in line.lower():
                        analysis["Errors"].append(line.strip())
                    elif "warning" in line.lower():
                        analysis["Warnings"].append(line.strip())
            return analysis
        except Exception as e:
            return {"error": f"Lỗi phân tích log: {e}"}

    def analyze_binary(self, file_path):
        try:
            analysis = {"Header": None, "Metadata": {}}
            with open(file_path, "rb") as binary_file:
                analysis["Header"] = binary_file.read(4).hex()
                binary_file.seek(10)
                analysis["Metadata"]["Key"] = struct.unpack("I", binary_file.read(4))[0]
            return analysis
        except Exception as e:
            return {"error": f"Lỗi phân tích nhị phân: {e}"}

    def export_report(self):
        file_name, _ = QtWidgets.QFileDialog.getSaveFileName(self, 'Lưu Báo Cáo', '', 'PDF Files (*.pdf)')
        if file_name:
            data = self.result_display.toPlainText().split('\n')
            self.export_to_pdf(data, file_name)
            self.result_display.append(f"Báo cáo đã được lưu tại {file_name}")

    @staticmethod
    def export_to_pdf(data, file_name):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_font('Arial', '', 'fonts/arial.ttf', uni=True)
        pdf.set_font('Arial', size=12)
        for line in data:
            pdf.cell(0, 10, txt=line, ln=True)
        pdf.output(file_name)

    def open_references(self):
        webbrowser.open('https://www.iec.ch/61850/')
        self.result_display.append("Đã mở trang tham khảo IEC 61850.")


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    main_window = OTFileAnalyzer()
    sys.exit(app.exec_())
