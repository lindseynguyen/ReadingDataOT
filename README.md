OT File Analyzer
OT File Analyzer is a PyQt5-based GUI application designed to analyze various file types (XML, logs, binaries) commonly used in Operational Technology (OT) environments. It offers detailed metadata extraction, file content analysis, and report generation in PDF format. This tool is particularly useful for working with configurations like SCL files (IEC 61850), system logs, and binary files.

Features
File and Folder Analysis:

Analyze individual files or an entire directory for metadata and content insights.
Support for various file types: XML, logs, and binary files.
Metadata Extraction:

Displays metadata such as file size, type, and the number of files in a folder.
File-Specific Analysis:

SCL Files (XML): Parses and extracts Logical Devices, Logical Nodes, and GOOSE messages.
Log Files: Identifies errors and warnings in text-based log files.
Binary Files: Reads binary headers and key metadata fields.
Report Generation:

Export analysis results to a detailed PDF report.
Reference Support:

Provides quick access to IEC 61850 standards for further research.
User-Friendly Interface:

Intuitive and interactive GUI for selecting files/folders, displaying results, and exporting reports.
Installation
Prerequisites
Python 3.6+
Dependencies:
PyQt5
python-magic
fpdf
struct
Installation Steps
Clone the repository:

bash
Sao chép mã
git clone https://github.com/lindseynguyen/ReadingDataOT.git
cd OTFileAnalyzer
Install the required dependencies:

bash
Sao chép mã
pip install PyQt5 python-magic fpdf
Run the application:

bash
Sao chép mã
python ot_file_analyzer.py
How to Use
Interface Overview
File/Folder Selection: Browse and select a file or folder to analyze.
Metadata Display: Shows basic details about the selected file/folder.
Analysis Results: Provides detailed content analysis based on file type.
Functional Buttons:
Phân Tích File: Analyze a single file.
Phân Tích Thư Mục: Analyze all files in a folder.
Xuất Báo Cáo: Export analysis results to a PDF.
Tham Khảo Nguồn: Open IEC 61850 references in a web browser.
Thoát: Exit the application.
File Analysis Workflow
Open the application.
Select a file or folder using the Browse button.
Click Phân Tích File or Phân Tích Thư Mục for analysis.
View results in the display area.
Export the analysis report using the Xuất Báo Cáo button.
Supported File Types
XML Files:

Detects and parses SCL files based on IEC 61850 standards.
Extracts Logical Devices, Logical Nodes, and GOOSE messages.
Log Files:

Searches for keywords such as error, warning, and timeout.
Categorizes findings into Errors and Warnings.
Binary Files:

Reads the first 4 bytes as a header (hex format).
Extracts key metadata using structured binary reading.
Other File Types:

Unsupported files are flagged as "File type not supported."
Exporting Reports
Click Xuất Báo Cáo.
Select the destination for the PDF file.
The exported report includes all analysis results displayed in the GUI.
References
IEC 61850 Standards
License
This project is licensed under the MIT License. Feel free to use and modify it.

Contributing
If you'd like to contribute, please fork the repository and create a pull request with your changes.

Let me know if you'd like any adjustments or additions to the README!
