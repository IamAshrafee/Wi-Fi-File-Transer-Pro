# Wi-Fi File Transfer

A professional-grade Wi-Fi file transfer application that allows you to easily share files between devices on the same network. Built with Python, Flask, and CustomTkinter.

## Features

- 🖥️ Modern GUI interface
- 📱 Cross-platform file sharing (Windows, Linux, Android, iOS)
- 🌐 Works offline using local network
- 📦 Drag & drop file upload
- 🔄 Real-time file list updates
- 📱 Mobile-responsive web interface
- 🔍 QR code scanning support
- 🔔 File reception notifications

## Requirements

- Python 3.8 or higher
- Dependencies listed in `requirements.txt`

## Installation

1. Clone this repository:

```bash
git clone https://github.com/yourusername/wifi-file-transfer.git
cd wifi-file-transfer
```

2. Create a virtual environment (recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Linux/Mac
venv\Scripts\activate     # On Windows
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

1. Run the application:

```bash
python main.py
```

2. Click "Start Server" in the GUI
3. Scan the QR code with your mobile device or enter the displayed IP address in any browser
4. Upload files through the web interface
5. Files will be saved in the `uploads` folder

## Creating an Executable

To create a standalone executable:

1. Install PyInstaller:

```bash
pip install pyinstaller
```

2. Create the executable:

```bash
pyinstaller --onefile --windowed --icon=assets/icon.ico --add-data "templates;templates" --add-data "static;static" main.py
```

The executable will be created in the `dist` folder.

## Security Note

This application is designed for use on trusted local networks only. Do not expose the server to the internet.

## License

MIT License - Feel free to use and modify for your needs.
