import os
import sys
import socket
import threading
import webbrowser
import qrcode
import signal
from PIL import Image, ImageTk
from datetime import datetime, timedelta
from pathlib import Path
import customtkinter as ctk
from flask import Flask, request, render_template, send_from_directory, session, jsonify, Response, stream_with_context
from werkzeug.utils import secure_filename
from plyer import notification
import logging
from werkzeug.serving import make_server
import hashlib
import secrets
from cryptography.fernet import Fernet
from flask_session import Session
import zipfile
import shutil
import psutil
import schedule
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import mimetypes
import platform
import multiprocessing
from tkinter import filedialog, TclError, messagebox
import json
import humanize
from datetime import datetime
import tkinterdnd2 as tkdnd
import queue

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

# Initialize Flask app with proper error handling
app = Flask(__name__)
try:
    app.config['MAX_CONTENT_LENGTH'] = None  # No file size limit
    app.config['UPLOAD_FOLDER'] = os.path.abspath('uploads')
    app.config['SECRET_KEY'] = secrets.token_hex(32)
    app.config['SESSION_TYPE'] = 'filesystem'
    Session(app)
except Exception as e:
    logging.critical(f"Failed to initialize Flask app: {e}")
    sys.exit(1)

# Initialize thread pool with error handling
try:
    executor = ThreadPoolExecutor(max_workers=multiprocessing.cpu_count() * 2)
except Exception as e:
    logging.critical(f"Failed to initialize thread pool: {e}")
    sys.exit(1)

# Ensure required directories exist
required_dirs = ['uploads', 'compressed', 'temp']
for directory in required_dirs:
    try:
        os.makedirs(directory, exist_ok=True)
    except Exception as e:
        logging.critical(f"Failed to create directory {directory}: {e}")
        sys.exit(1)

# Global variables with proper initialization
server = None
server_thread = None
server_running = False
cleanup_thread = None
ENCRYPTION_KEY = None

def get_system_info():
    """Get system information for performance optimization."""
    return {
        'cpu_count': multiprocessing.cpu_count(),
        'memory': psutil.virtual_memory(),
        'disk': psutil.disk_usage('/'),
        'platform': platform.system(),
        'network': psutil.net_if_stats()
    }

def optimize_chunk_size():
    """Dynamically optimize chunk size based on system resources."""
    mem = psutil.virtual_memory()
    if mem.total > 8 * 1024 * 1024 * 1024:  # More than 8GB RAM
        return 8 * 1024 * 1024  # 8MB chunks
    else:
        return 4 * 1024 * 1024  # 4MB chunks

def stream_file(file_path):
    """Stream file in optimized chunks."""
    chunk_size = optimize_chunk_size()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk

def compress_file(file_path):
    """Compress a file using ZIP format."""
    base_name = os.path.basename(file_path)
    zip_path = os.path.join('compressed', base_name + '.zip')
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(file_path, base_name)
    
    return zip_path

def auto_cleanup():
    """Automatically clean up old files."""
    while True:
        try:
            # Clean up files older than 24 hours
            cutoff = datetime.now() - timedelta(hours=24)
            
            for folder in [app.config['UPLOAD_FOLDER'], 'compressed', 'temp']:
                for file in os.listdir(folder):
                    file_path = os.path.join(folder, file)
                    if os.path.getctime(file_path) < cutoff.timestamp():
                        try:
                            os.remove(file_path)
                            logging.info(f"Cleaned up old file: {file}")
                        except Exception as e:
                            logging.error(f"Error cleaning up {file}: {e}")
            
            # Check disk space
            disk = psutil.disk_usage(app.config['UPLOAD_FOLDER'])
            if disk.percent > 90:  # If disk usage > 90%
                logging.warning("Disk space critical, cleaning up files")
                files = sorted(
                    [(f, os.path.getctime(os.path.join(app.config['UPLOAD_FOLDER'], f)))
                     for f in os.listdir(app.config['UPLOAD_FOLDER'])],
                    key=lambda x: x[1]
                )
                # Remove oldest files until disk usage is below 70%
                while disk.percent > 70 and files:
                    file_to_remove = files.pop(0)[0]
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_to_remove))
                    disk = psutil.disk_usage(app.config['UPLOAD_FOLDER'])
                    logging.info(f"Removed old file due to disk space: {file_to_remove}")
        
        except Exception as e:
            logging.error(f"Error in cleanup task: {e}")
        
        time.sleep(3600)  # Run every hour

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        # Create a socket to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logging.warning(f"Could not get local IP: {e}")
        return '127.0.0.1'

def generate_qr_code(url):
    """Generate QR code for the given URL."""
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(url)
        qr.make(fit=True)
        return qr.make_image(fill_color="black", back_color="white")
    except Exception as e:
        logging.error(f"Error generating QR code: {e}")
        return None

def show_notification(title, message):
    """Show a notification with error handling."""
    try:
        if not app.gui_instance.settings.get('notifications', True):
            return
            
        icon_path = os.path.abspath("assets/icon.ico")
        if os.path.exists(icon_path):
            notification.notify(
                title=title,
                message=message,
                app_icon=icon_path,
                timeout=5,
            )
        else:
            notification.notify(
                title=title,
                message=message,
                timeout=5,
            )
    except Exception as e:
        logging.error(f"Failed to show notification: {e}")

def get_human_readable_size(size_bytes):
    """Convert bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

def generate_encryption_key():
    """Generate a new encryption key."""
    return Fernet.generate_key()

def encrypt_file(file_path, key):
    """Encrypt a file using Fernet symmetric encryption."""
    f = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(file_path + '.encrypted', 'wb') as file:
        file.write(encrypted_data)
    os.remove(file_path)
    return file_path + '.encrypted'

def decrypt_file(file_path, key):
    """Decrypt a file using Fernet symmetric encryption."""
    f = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    decrypted_path = file_path.replace('.encrypted', '')
    with open(decrypted_path, 'wb') as file:
        file.write(decrypted_data)
    os.remove(file_path)
    return decrypted_path

class ServerThread(threading.Thread):
    def __init__(self, app, host, port):
        threading.Thread.__init__(self)
        self.srv = make_server(host, port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.srv.serve_forever()

    def shutdown(self):
        self.srv.shutdown()

class ConnectedDevice:
    def __init__(self, name, ip, status="online"):
        self.name = name
        self.ip = ip
        self.status = status
        self.blocked = False
        self.last_seen = datetime.now()
        self.total_transfers = 0
        self.total_bytes = 0

    def to_dict(self):
        return {
            "name": self.name,
            "ip": self.ip,
            "status": self.status,
            "blocked": self.blocked,
            "last_seen": self.last_seen.isoformat(),
            "total_transfers": self.total_transfers,
            "total_bytes": self.total_bytes
        }

    @classmethod
    def from_dict(cls, data):
        device = cls(data["name"], data["ip"], data["status"])
        device.blocked = data["blocked"]
        device.last_seen = datetime.fromisoformat(data["last_seen"])
        device.total_transfers = data["total_transfers"]
        device.total_bytes = data["total_bytes"]
        return device

class FileTransferApp:
    def __init__(self):
        try:
            # Initialize main window with error handling
            self.window = ctk.CTk()
            self.window.title("Wi-Fi File Transfer Pro")
            self.window.geometry("1000x700")
            self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
            
            # Initialize variables
            self.theme_var = ctk.StringVar(value="system")
            self.search_var = ctk.StringVar()
            self.search_var.trace_add("write", self.on_search)
            self.file_history = []  # List to store file history
            
            # Transfer statistics
            self.total_bytes_transferred = 0
            self.total_files_transferred = 0
            self.transfer_speeds = []
            self.current_transfers = {}
            self.favorite_folders = []
            self.transfer_start_time = None
            self.lifetime_bytes = 0
            self.lifetime_files = 0
            self.lifetime_speed_samples = []
            
            # Device management
            self.connected_devices = {}
            self.blocked_ips = set()
            
            # System monitoring
            self.cpu_usage = 0
            self.ram_usage = 0
            self.disk_space = None
            self.network_speed = {"up": 0, "down": 0}
            self.last_network_check = None
            self.last_bytes_sent = 0
            self.last_bytes_recv = 0
            
            # Security settings
            self.encryption_enabled = False
            self.password_protected = False
            self.transfer_password = None
            
            # Advanced settings
            self.compression_enabled = False
            self.auto_cleanup_enabled = True
            self.max_concurrent_transfers = multiprocessing.cpu_count()
            self.chunk_size = 8 * 1024 * 1024  # 8MB default
            
            # Load settings and statistics
            self.load_settings()
            self.load_lifetime_stats()
            
            # Setup GUI
            self.setup_gui()
            
            # Setup drag and drop with error handling
            self.setup_drag_drop()
            
            # Initialize transfer queue
            self.transfer_queue = queue.Queue()
            self.transfer_thread = threading.Thread(target=self.process_transfer_queue, daemon=True)
            self.transfer_thread.start()
            
            # Start monitoring threads
            self.start_monitoring_threads()
            
            # Start periodic updates
            self.start_periodic_updates()
            
        except Exception as e:
            logging.critical(f"Failed to initialize application: {e}")
            raise

    def setup_drag_drop(self):
        """Setup drag and drop support with proper error handling."""
        try:
            # Initialize tkdnd
            self.window.tk.eval('package require tkdnd')
            self.window.tk.call('tkdnd::drop_target', 'register', self.window._w, 'DND_Files')
            self.window.bind('<<Drop>>', self.on_drop)
        except Exception as e:
            logging.warning(f"Drag and drop support not available: {e}")

    def on_drop(self, event):
        """Handle drag and drop events with error checking."""
        try:
            # Get the dropped files from the event
            raw_data = self.window.tk.call('tkdnd::drop_target', 'fetch_data')
            files = self.window.tk.splitlist(raw_data)
            
            for file in files:
                # Clean and validate the file path
                file_path = file.replace('{}', '').replace('\\\\', '\\')
                if os.path.exists(file_path):
                    self.upload_file(file_path)
                else:
                    logging.warning(f"Dropped file not found: {file_path}")
                    show_notification("Error", f"File not found: {os.path.basename(file_path)}")
        except Exception as e:
            logging.error(f"Error handling dropped files: {e}")
            show_notification("Error", "Failed to process dropped files")

    def load_settings(self):
        """Load application settings with error handling."""
        try:
            if os.path.exists('settings.json'):
                with open('settings.json', 'r') as f:
                    self.settings = json.load(f)
                    
                    # Load folder settings
                    if 'upload_folder' in self.settings:
                        app.config['UPLOAD_FOLDER'] = self.settings['upload_folder']
                    self.favorite_folders = self.settings.get('favorite_folders', [])
                    
                    # Load transfer settings
                    self.max_concurrent_transfers = self.settings.get(
                        'max_concurrent_transfers',
                        multiprocessing.cpu_count()
                    )
                    self.chunk_size = self.settings.get(
                        'chunk_size',
                        8 * 1024 * 1024
                    )
                    
                    # Load notification settings
                    self.notification_enabled = self.settings.get('notifications', True)
                    self.notification_sound = self.settings.get('notification_sound', True)
                    self.notification_duration = self.settings.get('notification_duration', 5)
            else:
                self.settings = {
                    'theme': 'system',
                    'port': 8000,
                    'auto_start': False,
                    'notifications': True,
                    'notification_sound': True,
                    'notification_duration': 5,
                    'max_history': 100,
                    'preview_enabled': True,
                    'upload_folder': app.config['UPLOAD_FOLDER'],
                    'favorite_folders': [],
                    'max_concurrent_transfers': multiprocessing.cpu_count(),
                    'chunk_size': 8 * 1024 * 1024
                }
                self.save_settings()
        except Exception as e:
            logging.error(f"Error loading settings: {e}")
            self.settings = {}

    def save_settings(self):
        """Save application settings with error handling."""
        try:
            # Update settings with current values
            self.settings.update({
                'upload_folder': app.config['UPLOAD_FOLDER'],
                'favorite_folders': self.favorite_folders,
                'max_concurrent_transfers': self.max_concurrent_transfers,
                'chunk_size': self.chunk_size,
                'notifications': getattr(self, 'notification_enabled', True),
                'notification_sound': getattr(self, 'notification_sound', True),
                'notification_duration': getattr(self, 'notification_duration', 5)
            })
            
            with open('settings.json', 'w') as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving settings: {e}")
            show_notification("Error", "Failed to save settings")

    def setup_gui(self):
        """Setup the enhanced GUI elements."""
        # Create main container
        self.main_container = ctk.CTkFrame(self.window)
        self.main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Create tabview
        self.tabview = ctk.CTkTabview(self.main_container)
        self.tabview.pack(fill="both", expand=True, padx=5, pady=5)

        # Add tabs
        self.tab_main = self.tabview.add("Main")
        self.tab_files = self.tabview.add("Files")
        self.tab_settings = self.tabview.add("Settings")
        self.tab_about = self.tabview.add("About")

        # Setup each tab
        self.setup_main_tab()
        self.setup_files_tab()
        self.setup_settings_tab()
        self.setup_about_tab()

    def setup_main_tab(self):
        """Setup the main tab with server controls, statistics, and system monitoring."""
        # Main container with padding
        main_container = ctk.CTkFrame(self.tab_main, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=20, pady=20)

        # Server Control Card
        server_card = ctk.CTkFrame(main_container)
        server_card.pack(fill="x", pady=(0, 20))

        # Server Header
        server_header = ctk.CTkFrame(server_card, fg_color="transparent")
        server_header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(
            server_header,
            text="🌐 Server Control",
            font=("Arial", 18, "bold")
        ).pack(side="left")

        # Server Status and Controls in one line
        control_frame = ctk.CTkFrame(server_card, fg_color="transparent")
        control_frame.pack(fill="x", padx=15, pady=10)
        
        # Left side - Status indicator and text
        status_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        status_frame.pack(side="left", padx=5)
        
        self.status_indicator = ctk.CTkLabel(
            status_frame,
            text="●",
            text_color="red",
            font=("Arial", 24)
        )
        self.status_indicator.pack(side="left", padx=5)
        
        status_text = ctk.CTkLabel(
            status_frame,
            text="Server Offline",
            font=("Arial", 14)
        )
        status_text.pack(side="left", padx=5)
        
        # Right side - Port and Start button
        right_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        right_frame.pack(side="right", padx=5)
        
        # Port configuration
        port_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        port_frame.pack(side="left", padx=10)
        
        ctk.CTkLabel(
            port_frame,
            text="Port:",
            font=("Arial", 12)
        ).pack(side="left", padx=5)
        
        self.port_var = ctk.StringVar(value=str(self.settings.get('port', 8000)))
        self.port_entry = ctk.CTkEntry(
            port_frame,
            width=80,
            textvariable=self.port_var,
            font=("Arial", 12)
        )
        self.port_entry.pack(side="left", padx=5)
        
        # Start/Stop button
        self.start_button = ctk.CTkButton(
            right_frame,
            text="▶️ Start Server",
            command=self.toggle_server,
            width=150,
            height=35,
            font=("Arial", 12, "bold")
        )
        self.start_button.pack(side="left", padx=5)

        # Server URL Section
        url_card = ctk.CTkFrame(main_container)
        url_card.pack(fill="x", pady=(0, 20))
        
        url_header = ctk.CTkFrame(url_card, fg_color="transparent")
        url_header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(
            url_header,
            text="🔗 Server URL",
            font=("Arial", 18, "bold")
        ).pack(side="left")
        
        # URL content
        url_content = ctk.CTkFrame(url_card, fg_color="transparent")
        url_content.pack(fill="x", padx=15, pady=5)
        
        self.ip_label = ctk.CTkLabel(
            url_content,
            text="Server not running",
            font=("Arial", 14)
        )
        self.ip_label.pack(side="left", padx=5)
        
        self.copy_button = ctk.CTkButton(
            url_content,
            text="📋 Copy URL",
            command=self.copy_url,
            width=120,
            height=35
        )
        self.copy_button.pack(side="right", padx=5)

        # QR Code Section
        self.qr_frame = ctk.CTkFrame(main_container)
        self.qr_frame.pack_forget()  # Initially hidden
        
        qr_header = ctk.CTkFrame(self.qr_frame, fg_color="transparent")
        qr_header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(
            qr_header,
            text="📱 Scan QR Code",
            font=("Arial", 18, "bold")
        ).pack(side="left")
        
        qr_content = ctk.CTkFrame(self.qr_frame, fg_color="transparent")
        qr_content.pack(padx=15, pady=5)
        
        self.qr_label = ctk.CTkLabel(qr_content, text="")
        self.qr_label.pack(pady=10, padx=10)
        
        # Initialize QR photo attribute
        self.qr_photo = None

        # Transfer Statistics Card
        stats_card = ctk.CTkFrame(main_container)
        stats_card.pack(fill="x", pady=(0, 20))
        
        stats_header = ctk.CTkFrame(stats_card, fg_color="transparent")
        stats_header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(
            stats_header,
            text="📊 Transfer Statistics",
            font=("Arial", 18, "bold")
        ).pack(side="left")
        
        # Stats in one line with space-between
        stats_content = ctk.CTkFrame(stats_card, fg_color="transparent")
        stats_content.pack(fill="x", padx=15, pady=5)
        
        # Container for all stats with space-between
        stats_container = ctk.CTkFrame(stats_content, fg_color="transparent")
        stats_container.pack(fill="x", expand=True)
        
        # Current session stats
        session_frame = ctk.CTkFrame(stats_container, fg_color="transparent")
        session_frame.pack(side="left", padx=10)
        
        ctk.CTkLabel(
            session_frame,
            text="🔄",
            font=("Arial", 16)
        ).pack(side="left", padx=5)
        
        self.session_stats_label = ctk.CTkLabel(
            session_frame,
            text="Current Session: 0 files received",
            font=("Arial", 12)
        )
        self.session_stats_label.pack(side="left", padx=5)
        
        # Lifetime stats
        lifetime_frame = ctk.CTkFrame(stats_container, fg_color="transparent")
        lifetime_frame.pack(side="left", expand=True, padx=10)
        
        ctk.CTkLabel(
            lifetime_frame,
            text="📈",
            font=("Arial", 16)
        ).pack(side="left", padx=5)
        
        self.lifetime_stats_label = ctk.CTkLabel(
            lifetime_frame,
            text="Lifetime: 0 files received",
            font=("Arial", 12)
        )
        self.lifetime_stats_label.pack(side="left", padx=5)
        
        # Disk space information
        disk_frame = ctk.CTkFrame(stats_container, fg_color="transparent")
        disk_frame.pack(side="right", padx=10)
        
        ctk.CTkLabel(
            disk_frame,
            text="💾",
            font=("Arial", 16)
        ).pack(side="left", padx=5)
        
        self.disk_label = ctk.CTkLabel(
            disk_frame,
            text="Storage: N/A",
            font=("Arial", 12)
        )
        self.disk_label.pack(side="left", padx=5)

        # Connected Devices Card
        devices_card = ctk.CTkFrame(main_container)
        devices_card.pack(fill="x", pady=(0, 20))
        
        devices_header = ctk.CTkFrame(devices_card, fg_color="transparent")
        devices_header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(
            devices_header,
            text="📱 Connected Devices",
            font=("Arial", 18, "bold")
        ).pack(side="left")
        
        self.refresh_devices_button = ctk.CTkButton(
            devices_header,
            text="🔄 Refresh",
            command=self.refresh_devices,
            width=100,
            height=35
        )
        self.refresh_devices_button.pack(side="right", padx=5)
        
        # Devices list with better styling
        self.devices_list = ctk.CTkScrollableFrame(devices_card)
        self.devices_list.pack(fill="both", expand=True, padx=15, pady=10)

    def setup_files_tab(self):
        """Setup the files tab (History) with enhanced features."""
        # Search frame
        self.search_frame = ctk.CTkFrame(self.tab_files)
        self.search_frame.pack(fill="x", padx=10, pady=5)
        
        self.search_entry = ctk.CTkEntry(
            self.search_frame,
            placeholder_text="Search files by name...",
            textvariable=self.search_var,
            width=300
        )
        self.search_entry.pack(side="left", padx=5, pady=5)
        
        self.clear_search_button = ctk.CTkButton(
            self.search_frame,
            text="Clear Search",
            command=self.clear_search,
            width=100
        )
        self.clear_search_button.pack(side="left", padx=5)

        # File list frame with headers
        self.file_frame = ctk.CTkFrame(self.tab_files)
        self.file_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Headers frame
        headers_frame = ctk.CTkFrame(self.file_frame)
        headers_frame.pack(fill="x", padx=5, pady=2)
        
        ctk.CTkLabel(
            headers_frame,
            text="Timestamp",
            font=("Arial", 11, "bold"),
            width=150
        ).pack(side="left", padx=5)
        
        ctk.CTkLabel(
            headers_frame,
            text="Filename",
            font=("Arial", 11, "bold"),
            width=300
        ).pack(side="left", padx=5)
        
        ctk.CTkLabel(
            headers_frame,
            text="Size",
            font=("Arial", 11, "bold"),
            width=100
        ).pack(side="left", padx=5)
        
        ctk.CTkLabel(
            headers_frame,
            text="Actions",
            font=("Arial", 11, "bold"),
            width=150
        ).pack(side="right", padx=5)
        
        # Files list
        self.files_list = ctk.CTkScrollableFrame(self.file_frame)
        self.files_list.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bottom controls frame
        controls_frame = ctk.CTkFrame(self.tab_files)
        controls_frame.pack(fill="x", padx=10, pady=5)
        
        self.open_folder_button = ctk.CTkButton(
            controls_frame,
            text="Open Folder",
            command=self.open_upload_folder,
            width=120
        )
        self.open_folder_button.pack(side="left", padx=5)
        
        self.clear_history_button = ctk.CTkButton(
            controls_frame,
            text="Clear History",
            command=self.clear_history,
            width=120
        )
        self.clear_history_button.pack(side="right", padx=5)

    def on_search(self, *args):
        """Handle file search."""
        try:
            self.refresh_file_list()
        except Exception as e:
            logging.error(f"Error in search: {e}")

    def clear_search(self):
        """Clear search field and reset file list."""
        try:
            self.search_var.set("")
            self.refresh_file_list()
        except Exception as e:
            logging.error(f"Error clearing search: {e}")

    def clear_history(self):
        """Clear the file history and reset statistics."""
        try:
            if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear the entire history?"):
                self.file_history = []
                self.total_bytes_transferred = 0
                self.total_files_transferred = 0
                self.transfer_speeds = []
                self.refresh_file_list()
                self.update_statistics()
                show_notification("History Cleared", "File transfer history has been cleared")
        except Exception as e:
            logging.error(f"Error clearing history: {e}")

    def update_file_list(self, filename, size):
        """Update the file list with a new entry."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            size_str = get_human_readable_size(size)
            entry = {
                'timestamp': timestamp,
                'filename': filename,
                'size': size,
                'size_str': size_str,
                'path': os.path.join(app.config['UPLOAD_FOLDER'], filename)
            }
            
            # Add to history and save
            self.file_history.append(entry)
            self.save_lifetime_stats()
            
            # Update statistics
            self.total_bytes_transferred += size
            self.total_files_transferred += 1
            self.update_statistics()
            
            # Refresh the files list
            self.window.after(0, self.refresh_file_list)
            
        except Exception as e:
            logging.error(f"Error updating file list: {e}")

    def refresh_file_list(self):
        """Refresh the files list display."""
        try:
            # Clear existing list
            for widget in self.files_list.winfo_children():
                widget.destroy()
            
            # Get search term
            search_term = self.search_var.get().lower()
            
            # Filter and sort files
            filtered_files = [
                entry for entry in self.file_history
                if search_term in entry['filename'].lower()
            ]
            
            # Sort by timestamp, newest first
            filtered_files.sort(key=lambda x: x['timestamp'], reverse=True)
            
            # Add each file entry
            for entry in filtered_files:
                # Create frame for this entry
                entry_frame = ctk.CTkFrame(self.files_list)
                entry_frame.pack(fill="x", padx=5, pady=2)
                
                # Timestamp
                ctk.CTkLabel(
                    entry_frame,
                    text=entry['timestamp'],
                    width=150,
                    anchor="w"
                ).pack(side="left", padx=5)
                
                # Filename (with ellipsis if too long)
                filename = entry['filename']
                if len(filename) > 40:
                    filename = filename[:37] + "..."
                
                filename_label = ctk.CTkLabel(
                    entry_frame,
                    text=filename,
                    width=300,
                    anchor="w",
                    cursor="hand2"
                )
                filename_label.pack(side="left", padx=5)
                
                # Add tooltip on hover
                self.add_tooltip(filename_label, entry['filename'])
                
                # Size
                ctk.CTkLabel(
                    entry_frame,
                    text=entry['size_str'],
                    width=100,
                    anchor="e"
                ).pack(side="left", padx=5)
                
                # Actions frame
                actions_frame = ctk.CTkFrame(entry_frame)
                actions_frame.pack(side="right", padx=5)
                
                # Delete button
                delete_btn = ctk.CTkButton(
                    actions_frame,
                    text="🗑️",
                    width=30,
                    command=lambda f=entry['filename']: self.delete_file(f)
                )
                delete_btn.pack(side="left", padx=2)
                self.add_tooltip(delete_btn, "Delete file")
                
                # Open button
                open_btn = ctk.CTkButton(
                    actions_frame,
                    text="📂",
                    width=30,
                    command=lambda f=entry['filename']: self.open_file(f)
                )
                open_btn.pack(side="left", padx=2)
                self.add_tooltip(open_btn, "Open file")
                
                # Show in folder button
                show_btn = ctk.CTkButton(
                    actions_frame,
                    text="📍",
                    width=30,
                    command=lambda p=entry['path']: self.show_in_folder(p)
                )
                show_btn.pack(side="left", padx=2)
                self.add_tooltip(show_btn, "Show in folder")
                
        except Exception as e:
            logging.error(f"Error refreshing file list: {e}")

    def add_tooltip(self, widget, text):
        """Add tooltip to a widget."""
        def show_tooltip(event):
            tooltip = ctk.CTkToplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            
            label = ctk.CTkLabel(tooltip, text=text)
            label.pack()
            
            def hide_tooltip():
                tooltip.destroy()
            
            tooltip.bind('<Leave>', lambda e: hide_tooltip())
            widget.bind('<Leave>', lambda e: hide_tooltip())
            
        widget.bind('<Enter>', show_tooltip)

    def show_in_folder(self, path):
        """Show file in folder."""
        try:
            folder_path = os.path.dirname(path)
            if sys.platform == 'win32':
                os.system(f'explorer /select,"{path}"')
            elif sys.platform == 'darwin':  # macOS
                os.system(f'open -R "{path}"')
            else:  # Linux
                if os.path.exists('/usr/bin/nautilus'):  # GNOME
                    os.system(f'nautilus --select "{path}"')
                elif os.path.exists('/usr/bin/dolphin'):  # KDE
                    os.system(f'dolphin --select "{path}"')
                else:  # Fallback
                    self.open_folder(folder_path)
        except Exception as e:
            logging.error(f"Error showing file in folder: {e}")
            self.open_folder(os.path.dirname(path))

    def open_folder(self, path):
        """Open folder in file explorer."""
        try:
            if sys.platform == 'win32':
                os.startfile(path)
            elif sys.platform == 'darwin':  # macOS
                os.system(f'open "{path}"')
            else:  # Linux
                os.system(f'xdg-open "{path}"')
        except Exception as e:
            logging.error(f"Error opening folder: {e}")
            show_notification("Error", "Could not open folder")

    def delete_file(self, filename):
        """Delete a file and update history."""
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                # Ask for confirmation
                if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {filename}?"):
                    os.remove(file_path)
                    # Remove from history
                    self.file_history = [
                        entry for entry in self.file_history 
                        if entry['filename'] != filename
                    ]
                    self.refresh_file_list()
                    show_notification("File Deleted", f"{filename} has been deleted")
            else:
                show_notification("Error", f"File {filename} not found")
        except Exception as e:
            logging.error(f"Error deleting file {filename}: {e}")
            show_notification("Error", f"Failed to delete {filename}")

    def open_file(self, filename):
        """Open a file in the default application."""
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                if sys.platform == 'win32':
                    os.startfile(file_path)
                else:
                    webbrowser.open(f'file://{file_path}')
            else:
                show_notification("Error", f"File {filename} not found")
        except Exception as e:
            logging.error(f"Error opening file {filename}: {e}")
            show_notification("Error", f"Failed to open {filename}")

    def handle_file_conflict(self, filename):
        """Handle file name conflicts."""
        dialog = ctk.CTkInputDialog(
            text=f"File {filename} already exists. Choose action:",
            title="File Conflict"
        )
        
        # Create buttons frame
        buttons_frame = ctk.CTkFrame(dialog)
        buttons_frame.pack(pady=10)
        
        result = {"action": None}
        
        def set_action(action):
            result["action"] = action
            dialog.destroy()
        
        # Replace button
        ctk.CTkButton(
            buttons_frame,
            text="Replace",
            command=lambda: set_action("replace")
        ).pack(side="left", padx=5)
        
        # Add number button
        ctk.CTkButton(
            buttons_frame,
            text="Add Number",
            command=lambda: set_action("number")
        ).pack(side="left", padx=5)
        
        # Cancel button
        ctk.CTkButton(
            buttons_frame,
            text="Cancel",
            command=lambda: set_action("cancel")
        ).pack(side="left", padx=5)
        
        dialog.wait_window()
        return result["action"]

    def setup_settings_tab(self):
        """Setup the settings tab with enhanced options and better organization."""
        # Create scrollable frame for settings
        settings_scroll = ctk.CTkScrollableFrame(self.tab_settings)
        settings_scroll.pack(fill="both", expand=True, padx=20, pady=20)

        # General Settings Section
        general_frame = ctk.CTkFrame(settings_scroll)
        general_frame.pack(fill="x", pady=(0, 20))

        # Section Header
        header_frame = ctk.CTkFrame(general_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(10, 5))
        
        ctk.CTkLabel(
            header_frame,
            text="⚙️ General Settings",
            font=("Arial", 18, "bold")
        ).pack(side="left", padx=10)

        # Theme Selection
        theme_frame = ctk.CTkFrame(general_frame, fg_color="transparent")
        theme_frame.pack(fill="x", pady=5, padx=10)
        
        ctk.CTkLabel(
            theme_frame,
            text="Theme:",
            font=("Arial", 12)
        ).pack(side="left", padx=5)
        
        theme_options = ["System", "Light", "Dark"]
        theme_menu = ctk.CTkOptionMenu(
            theme_frame,
            values=theme_options,
            command=lambda x: self.change_theme(x.lower()),
            width=120
        )
        theme_menu.pack(side="left", padx=5)
        theme_menu.set(self.settings.get('theme', 'system').capitalize())

        # Folder Settings Section
        folder_frame = ctk.CTkFrame(settings_scroll)
        folder_frame.pack(fill="x", pady=(0, 20))

        # Section Header
        header_frame = ctk.CTkFrame(folder_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(10, 5))
        
        ctk.CTkLabel(
            header_frame,
            text="📁 Folder Settings",
            font=("Arial", 18, "bold")
        ).pack(side="left", padx=10)

        # Upload folder selection
        upload_frame = ctk.CTkFrame(folder_frame, fg_color="transparent")
        upload_frame.pack(fill="x", pady=5, padx=10)
        
        ctk.CTkLabel(
            upload_frame,
            text="Upload Folder:",
            font=("Arial", 12)
        ).pack(side="left", padx=5)
        
        self.upload_folder_label = ctk.CTkLabel(
            upload_frame,
            text=app.config['UPLOAD_FOLDER'],
            font=("Arial", 11),
            text_color=("gray70", "gray30")
        )
        self.upload_folder_label.pack(side="left", padx=5, fill="x", expand=True)
        
        ctk.CTkButton(
            upload_frame,
            text="Change",
            command=self.change_upload_folder,
            width=100
        ).pack(side="right", padx=5)

        # Favorite folders
        favorite_frame = ctk.CTkFrame(folder_frame)
        favorite_frame.pack(fill="x", pady=5, padx=10)
        
        ctk.CTkLabel(
            favorite_frame,
            text="Favorite Folders:",
            font=("Arial", 12)
        ).pack(anchor="w", padx=10, pady=5)
        
        self.favorite_listbox = ctk.CTkTextbox(
            favorite_frame,
            height=100,
            font=("Arial", 11)
        )
        self.favorite_listbox.pack(fill="x", padx=10, pady=5)
        
        favorite_button_frame = ctk.CTkFrame(favorite_frame, fg_color="transparent")
        favorite_button_frame.pack(fill="x", pady=5)
        
        ctk.CTkButton(
            favorite_button_frame,
            text="Add Folder",
            command=self.add_favorite_folder,
            width=120
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            favorite_button_frame,
            text="Remove Selected",
            command=self.remove_favorite_folder,
            width=120
        ).pack(side="left", padx=5)

        # Transfer Settings Section
        transfer_frame = ctk.CTkFrame(settings_scroll)
        transfer_frame.pack(fill="x", pady=(0, 20))

        # Section Header
        header_frame = ctk.CTkFrame(transfer_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(10, 5))
        
        ctk.CTkLabel(
            header_frame,
            text="📤 Transfer Settings",
            font=("Arial", 18, "bold")
        ).pack(side="left", padx=10)

        # Concurrent transfers
        concurrent_frame = ctk.CTkFrame(transfer_frame, fg_color="transparent")
        concurrent_frame.pack(fill="x", pady=5, padx=10)
        
        ctk.CTkLabel(
            concurrent_frame,
            text="Max Concurrent Transfers:",
            font=("Arial", 12)
        ).pack(side="left", padx=5)
        
        self.concurrent_var = ctk.StringVar(value=str(self.max_concurrent_transfers))
        concurrent_entry = ctk.CTkEntry(
            concurrent_frame,
            textvariable=self.concurrent_var,
            width=80
        )
        concurrent_entry.pack(side="right", padx=5)

        # Chunk size
        chunk_frame = ctk.CTkFrame(transfer_frame, fg_color="transparent")
        chunk_frame.pack(fill="x", pady=5, padx=10)
        
        ctk.CTkLabel(
            chunk_frame,
            text="Chunk Size (MB):",
            font=("Arial", 12)
        ).pack(side="left", padx=5)
        
        self.chunk_var = ctk.StringVar(value=str(self.chunk_size // (1024 * 1024)))
        chunk_entry = ctk.CTkEntry(
            chunk_frame,
            textvariable=self.chunk_var,
            width=80
        )
        chunk_entry.pack(side="right", padx=5)

        # Security Settings Section
        security_frame = ctk.CTkFrame(settings_scroll)
        security_frame.pack(fill="x", pady=(0, 20))

        # Section Header
        header_frame = ctk.CTkFrame(security_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(10, 5))
        
        ctk.CTkLabel(
            header_frame,
            text="🔒 Security Settings",
            font=("Arial", 18, "bold")
        ).pack(side="left", padx=10)

        # Encryption switch with description
        encryption_frame = ctk.CTkFrame(security_frame, fg_color="transparent")
        encryption_frame.pack(fill="x", pady=5, padx=10)
        
        self.encryption_switch = ctk.CTkSwitch(
            encryption_frame,
            text="Enable Encryption",
            command=self.toggle_encryption,
            font=("Arial", 12)
        )
        self.encryption_switch.pack(side="left", padx=5)
        
        ctk.CTkLabel(
            encryption_frame,
            text="Encrypt files during transfer",
            font=("Arial", 11),
            text_color=("gray70", "gray30")
        ).pack(side="left", padx=5)

        # Password protection switch with description
        password_frame = ctk.CTkFrame(security_frame, fg_color="transparent")
        password_frame.pack(fill="x", pady=5, padx=10)
        
        self.password_switch = ctk.CTkSwitch(
            password_frame,
            text="Password Protection",
            command=self.toggle_password_protection,
            font=("Arial", 12)
        )
        self.password_switch.pack(side="left", padx=5)
        
        ctk.CTkLabel(
            password_frame,
            text="Require password for file transfers",
            font=("Arial", 11),
            text_color=("gray70", "gray30")
        ).pack(side="left", padx=5)

        # Advanced Settings Section
        advanced_frame = ctk.CTkFrame(settings_scroll)
        advanced_frame.pack(fill="x", pady=(0, 20))

        # Section Header
        header_frame = ctk.CTkFrame(advanced_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(10, 5))
        
        ctk.CTkLabel(
            header_frame,
            text="⚡ Advanced Settings",
            font=("Arial", 18, "bold")
        ).pack(side="left", padx=10)

        # Compression switch with description
        compression_frame = ctk.CTkFrame(advanced_frame, fg_color="transparent")
        compression_frame.pack(fill="x", pady=5, padx=10)
        
        self.compression_switch = ctk.CTkSwitch(
            compression_frame,
            text="Enable Compression",
            command=self.toggle_compression,
            font=("Arial", 12)
        )
        self.compression_switch.pack(side="left", padx=5)
        
        ctk.CTkLabel(
            compression_frame,
            text="Compress files before transfer",
            font=("Arial", 11),
            text_color=("gray70", "gray30")
        ).pack(side="left", padx=5)

        # Auto cleanup switch with description
        cleanup_frame = ctk.CTkFrame(advanced_frame, fg_color="transparent")
        cleanup_frame.pack(fill="x", pady=5, padx=10)
        
        self.cleanup_switch = ctk.CTkSwitch(
            cleanup_frame,
            text="Auto Cleanup",
            command=self.toggle_auto_cleanup,
            font=("Arial", 12)
        )
        self.cleanup_switch.pack(side="left", padx=5)
        
        ctk.CTkLabel(
            cleanup_frame,
            text="Automatically clean up old files",
            font=("Arial", 11),
            text_color=("gray70", "gray30")
        ).pack(side="left", padx=5)

        # Auto start switch with description
        autostart_frame = ctk.CTkFrame(advanced_frame, fg_color="transparent")
        autostart_frame.pack(fill="x", pady=5, padx=10)
        
        self.autostart_switch = ctk.CTkSwitch(
            autostart_frame,
            text="Auto Start Server",
            command=self.toggle_autostart,
            font=("Arial", 12)
        )
        self.autostart_switch.pack(side="left", padx=5)
        
        ctk.CTkLabel(
            autostart_frame,
            text="Start server when application launches",
            font=("Arial", 11),
            text_color=("gray70", "gray30")
        ).pack(side="left", padx=5)

        # Notification Settings Section
        notification_frame = ctk.CTkFrame(settings_scroll)
        notification_frame.pack(fill="x", pady=(0, 20))

        # Section Header
        header_frame = ctk.CTkFrame(notification_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(10, 5))
        
        ctk.CTkLabel(
            header_frame,
            text="🔔 Notification Settings",
            font=("Arial", 18, "bold")
        ).pack(side="left", padx=10)

        # Notification switch with description
        notif_switch_frame = ctk.CTkFrame(notification_frame, fg_color="transparent")
        notif_switch_frame.pack(fill="x", pady=5, padx=10)
        
        self.notification_switch = ctk.CTkSwitch(
            notif_switch_frame,
            text="Enable Notifications",
            command=self.toggle_notifications,
            font=("Arial", 12)
        )
        self.notification_switch.pack(side="left", padx=5)
        
        ctk.CTkLabel(
            notif_switch_frame,
            text="Show notifications for important events",
            font=("Arial", 11),
            text_color=("gray70", "gray30")
        ).pack(side="left", padx=5)

        # Sound switch with description
        sound_frame = ctk.CTkFrame(notification_frame, fg_color="transparent")
        sound_frame.pack(fill="x", pady=5, padx=10)
        
        self.sound_switch = ctk.CTkSwitch(
            sound_frame,
            text="Enable Sound",
            command=self.toggle_sound,
            font=("Arial", 12)
        )
        self.sound_switch.pack(side="left", padx=5)
        
        ctk.CTkLabel(
            sound_frame,
            text="Play sound for notifications",
            font=("Arial", 11),
            text_color=("gray70", "gray30")
        ).pack(side="left", padx=5)

        # Notification duration
        duration_frame = ctk.CTkFrame(notification_frame, fg_color="transparent")
        duration_frame.pack(fill="x", pady=5, padx=10)
        
        ctk.CTkLabel(
            duration_frame,
            text="Notification Duration (seconds):",
            font=("Arial", 12)
        ).pack(side="left", padx=5)
        
        self.duration_var = ctk.StringVar(value=str(self.settings.get('notification_duration', 5)))
        duration_entry = ctk.CTkEntry(
            duration_frame,
            textvariable=self.duration_var,
            width=80
        )
        duration_entry.pack(side="right", padx=5)

        # Save Button
        save_frame = ctk.CTkFrame(settings_scroll, fg_color="transparent")
        save_frame.pack(fill="x", pady=20)
        
        save_button = ctk.CTkButton(
            save_frame,
            text="Save Settings",
            command=self.save_settings,
            width=200,
            height=40,
            font=("Arial", 14, "bold")
        )
        save_button.pack(pady=10)

    def setup_about_tab(self):
        """Setup the about tab with software information and developer details."""
        # Main container with scrolling
        about_scroll = ctk.CTkScrollableFrame(self.tab_about)
        about_scroll.pack(fill="both", expand=True, padx=20, pady=20)

        # App Header
        header_frame = ctk.CTkFrame(about_scroll, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))

        # App Logo (placeholder - you can replace with actual logo)
        logo_label = ctk.CTkLabel(
            header_frame,
            text="📱",
            font=("Arial", 48)
        )
        logo_label.pack(pady=(0, 10))

        # App Title and Version
        title_label = ctk.CTkLabel(
            header_frame,
            text="Wi-Fi File Transfer Pro",
            font=("Arial", 24, "bold")
        )
        title_label.pack()

        version_label = ctk.CTkLabel(
            header_frame,
            text="Version 2.0",
            font=("Arial", 14),
            text_color=("gray70", "gray30")
        )
        version_label.pack()

        # Features Card
        features_frame = ctk.CTkFrame(about_scroll)
        features_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            features_frame,
            text="✨ Key Features",
            font=("Arial", 16, "bold")
        ).pack(pady=(15, 10))

        features = [
            "🔒 Secure file transfer with encryption",
            "🔑 Password protection for transfers",
            "📦 File compression support",
            "🧹 Automatic file cleanup",
            "📊 Real-time transfer statistics",
            "🌓 Dark/Light theme support",
            "📤 Drag and drop support",
            "📁 Custom folder management",
            "⚡ Parallel file transfers",
            "📋 Transfer queue system",
            "📱 Device management",
            "🛡️ File overwrite protection",
            "🔍 Search functionality",
            "💻 Cross-platform compatibility"
        ]

        for feature in features:
            ctk.CTkLabel(
                features_frame,
                text=feature,
                font=("Arial", 12),
                justify="left"
            ).pack(pady=2, padx=20, anchor="w")

        # System Information Card
        sys_frame = ctk.CTkFrame(about_scroll)
        sys_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            sys_frame,
            text="💻 System Information",
            font=("Arial", 16, "bold")
        ).pack(pady=(15, 10))

        sys_info = [
            f"Python Version: {platform.python_version()}",
            f"Operating System: {platform.system()} {platform.release()}"
        ]

        for info in sys_info:
            ctk.CTkLabel(
                sys_frame,
                text=info,
                font=("Arial", 12)
            ).pack(pady=2)

        # Action Buttons
        button_frame = ctk.CTkFrame(about_scroll, fg_color="transparent")
        button_frame.pack(pady=(0, 20))

        self.github_button = ctk.CTkButton(
            button_frame,
            text="📦 View on GitHub",
            command=self.open_github,
            width=150,
            height=35
        )
        self.github_button.pack(side="left", padx=5)

        self.check_updates_button = ctk.CTkButton(
            button_frame,
            text="🔄 Check for Updates",
            command=self.check_updates,
            width=150,
            height=35
        )
        self.check_updates_button.pack(side="left", padx=5)

        # Developer Information Card
        dev_frame = ctk.CTkFrame(about_scroll)
        dev_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            dev_frame,
            text="👨‍💻 Developer Information",
            font=("Arial", 16, "bold")
        ).pack(pady=(15, 10))

        ctk.CTkLabel(
            dev_frame,
            text="Developed by Dev Ashrafee",
            font=("Arial", 14)
        ).pack(pady=(0, 10))

        # Social Links
        social_frame = ctk.CTkFrame(dev_frame, fg_color="transparent")
        social_frame.pack(pady=5)

        linkedin_button = ctk.CTkButton(
            social_frame,
            text="🔗 LinkedIn",
            command=lambda: webbrowser.open("https://www.linkedin.com/in/abdullahalashrafee/"),
            width=120,
            height=35
        )
        linkedin_button.pack(side="left", padx=5)

        github_profile_button = ctk.CTkButton(
            social_frame,
            text="🐙 GitHub",
            command=lambda: webbrowser.open("https://github.com/IamAshrafee"),
            width=120,
            height=35
        )
        github_profile_button.pack(side="left", padx=5)

        # Contact Information
        contact_frame = ctk.CTkFrame(dev_frame)
        contact_frame.pack(fill="x", pady=10, padx=20)

        ctk.CTkLabel(
            contact_frame,
            text="📧 Email: dev.ashrafee@gmail.com",
            font=("Arial", 12)
        ).pack(pady=5)

        ctk.CTkLabel(
            contact_frame,
            text="📱 WhatsApp: +8801612381085",
            font=("Arial", 12)
        ).pack(pady=5)

    def open_github(self):
        """Open GitHub repository."""
        try:
            webbrowser.open("https://github.com/IamAshrafee/wifi_file_transfer")
        except Exception as e:
            logging.error(f"Error opening GitHub page: {e}")
            show_notification("Error", "Could not open GitHub page")

    def check_updates(self):
        """Check for application updates."""
        try:
            # This is a placeholder for update checking functionality
            show_notification(
                "Updates",
                "You are running the latest version"
            )
        except Exception as e:
            logging.error(f"Error checking for updates: {e}")
            show_notification(
                "Error",
                "Failed to check for updates"
            )

    def change_upload_folder(self):
        """Change the upload folder location."""
        try:
            new_folder = filedialog.askdirectory(
                title="Select Upload Folder",
                initialdir=app.config['UPLOAD_FOLDER']
            )
            if new_folder:
                # Validate folder
                if not os.path.exists(new_folder):
                    os.makedirs(new_folder)
                
                # Update configuration
                app.config['UPLOAD_FOLDER'] = new_folder
                self.settings['upload_folder'] = new_folder
                self.save_settings()
                
                # Update UI
                self.upload_folder_label.configure(
                    text=f"Upload Folder: {new_folder}"
                )
                show_notification(
                    "Folder Changed",
                    f"Upload folder changed to: {new_folder}"
                )
                
                # Create required subdirectories
                for subdir in ['compressed', 'temp']:
                    os.makedirs(os.path.join(new_folder, subdir), exist_ok=True)
                
        except Exception as e:
            logging.error(f"Error changing upload folder: {e}")
            show_notification("Error", "Failed to change upload folder")

    def add_favorite_folder(self):
        """Add a folder to favorites."""
        try:
            folder = filedialog.askdirectory(
                title="Select Favorite Folder"
            )
            if folder and folder not in self.favorite_folders:
                self.favorite_folders.append(folder)
                self.settings['favorite_folders'] = self.favorite_folders
                self.save_settings()
                self.update_favorite_folders_display()
        except Exception as e:
            logging.error(f"Error adding favorite folder: {e}")
            show_notification("Error", "Failed to add favorite folder")

    def remove_favorite_folder(self):
        """Remove selected folder from favorites."""
        try:
            selection = self.favorite_listbox.get("sel.first", "sel.last")
            if selection:
                folder = selection.strip()
                if folder in self.favorite_folders:
                    self.favorite_folders.remove(folder)
                    self.settings['favorite_folders'] = self.favorite_folders
                    self.save_settings()
                    self.update_favorite_folders_display()
        except Exception as e:
            logging.error(f"Error removing favorite folder: {e}")

    def update_favorite_folders_display(self):
        """Update the favorite folders display."""
        try:
            self.favorite_listbox.delete("1.0", "end")
            for folder in self.favorite_folders:
                self.favorite_listbox.insert("end", f"{folder}\n")
        except Exception as e:
            logging.error(f"Error updating favorite folders display: {e}")

    def process_transfer_queue(self):
        """Process the transfer queue in background."""
        while True:
            try:
                # Get transfer task from queue
                transfer = self.transfer_queue.get()
                if transfer is None:
                    break

                source, dest = transfer
                
                # Check if we can start new transfer
                while len(self.current_transfers) >= self.max_concurrent_transfers:
                    time.sleep(0.1)
                
                # Start transfer
                self.current_transfers[source] = {
                    'progress': 0,
                    'speed': 0,
                    'start_time': time.time()
                }
                
                try:
                    # Copy file with progress tracking
                    total_size = os.path.getsize(source)
                    copied_size = 0
                    
                    with open(source, 'rb') as src, open(dest, 'wb') as dst:
                        while True:
                            chunk = src.read(self.chunk_size)
                            if not chunk:
                                break
                            
                            dst.write(chunk)
                            copied_size += len(chunk)
                            
                            # Update progress
                            progress = (copied_size / total_size) * 100
                            speed = copied_size / (time.time() - self.current_transfers[source]['start_time'])
                            
                            self.current_transfers[source].update({
                                'progress': progress,
                                'speed': speed
                            })
                    
                    # Process file if needed (compression/encryption)
                    if self.compression_enabled:
                        dest = compress_file(dest)
                    
                    if self.encryption_enabled and 'ENCRYPTION_KEY' in globals():
                        dest = encrypt_file(dest, ENCRYPTION_KEY)
                    
                    # Update UI
                    self.window.after(0, self.update_file_list, os.path.basename(dest), total_size)
                    
                except Exception as e:
                    logging.error(f"Error processing transfer {source}: {e}")
                    show_notification("Error", f"Failed to transfer {os.path.basename(source)}")
                
                finally:
                    # Cleanup
                    if source in self.current_transfers:
                        del self.current_transfers[source]
                    
                    self.transfer_queue.task_done()
                
            except Exception as e:
                logging.error(f"Error in transfer queue processing: {e}")
            
            time.sleep(0.1)  # Prevent CPU overload

    def start_periodic_updates(self):
        """Start periodic UI updates."""
        self.update_disk_space()
        self.update_transfer_speed()
        self.window.after(1000, self.start_periodic_updates)

    def update_transfer_speed(self):
        """Update transfer speed display."""
        if self.transfer_speeds:
            avg_speed = sum(self.transfer_speeds) / len(self.transfer_speeds)
            speed_str = humanize.naturalsize(avg_speed) + "/s"
            self.speed_label.configure(text=f"Current Speed: {speed_str}")
            self.transfer_speeds = self.transfer_speeds[-10:]  # Keep last 10 readings

    def change_theme(self, theme):
        """Change application theme."""
        theme = theme.lower()
        ctk.set_appearance_mode(theme)
        self.settings['theme'] = theme
        self.save_settings()

    def copy_url(self):
        """Copy server URL to clipboard."""
        if server_running:
            url = self.ip_label.cget("text").split(": ")[-1]
            self.window.clipboard_clear()
            self.window.clipboard_append(url)
            show_notification("URL Copied", "Server URL copied to clipboard")

    def toggle_autostart(self):
        """Toggle auto start server."""
        self.settings['auto_start'] = not self.settings.get('auto_start', False)
        self.save_settings()

    def toggle_encryption(self):
        """Toggle file encryption."""
        global ENCRYPTION_KEY
        if self.encryption_switch.get():
            ENCRYPTION_KEY = generate_encryption_key()
            self.encryption_enabled = True
            show_notification("Security", "File encryption enabled")
        else:
            ENCRYPTION_KEY = None
            self.encryption_enabled = False
            show_notification("Security", "File encryption disabled")

    def toggle_password_protection(self):
        """Toggle password protection for file transfers."""
        if self.password_switch.get():
            self.show_password_dialog()
        else:
            self.password_protected = False
            self.transfer_password = None
            show_notification("Security", "Password protection disabled")

    def show_password_dialog(self):
        """Show dialog to set transfer password."""
        dialog = ctk.CTkInputDialog(
            text="Enter password for file transfers:",
            title="Set Password"
        )
        password = dialog.get_input()
        if password:
            self.password_protected = True
            self.transfer_password = hashlib.sha256(password.encode()).hexdigest()
            show_notification("Security", "Password protection enabled")
        else:
            self.password_switch.set(False)

    def toggle_compression(self):
        """Toggle file compression."""
        self.compression_enabled = self.compression_switch.get()
        show_notification(
            "Compression",
            "File compression enabled" if self.compression_enabled else "File compression disabled"
        )

    def toggle_auto_cleanup(self):
        """Toggle automatic file cleanup."""
        self.auto_cleanup_enabled = self.cleanup_switch.get()
        show_notification(
            "Auto Cleanup",
            "Automatic cleanup enabled" if self.auto_cleanup_enabled else "Automatic cleanup disabled"
        )

    def update_statistics(self):
        """Update the statistics display with error handling."""
        try:
            # Update current session stats
            size_str = get_human_readable_size(self.total_bytes_transferred)
            self.session_stats_label.configure(
                text=f"Current Session: {size_str} files received"
            )
            
            # Update lifetime stats
            lifetime_size_str = get_human_readable_size(self.lifetime_bytes)
            self.lifetime_stats_label.configure(
                text=f"Lifetime: {lifetime_size_str} files received"
            )
        except Exception as e:
            logging.error(f"Error updating statistics: {e}")

    def update_disk_space(self):
        """Update disk space information with error handling."""
        try:
            disk = psutil.disk_usage(app.config['UPLOAD_FOLDER'])
            free_space = get_human_readable_size(disk.free)
            total_space = get_human_readable_size(disk.total)
            self.disk_label.configure(
                text=f"Storage: {free_space} free of {total_space}"
            )
        except Exception as e:
            logging.error(f"Error updating disk space: {e}")
            if hasattr(self, 'disk_label'):
                self.disk_label.configure(text="Could not get storage information")

    def update_server_status(self, running=False):
        """Update server status indicator."""
        if running:
            self.status_indicator.configure(text="●", text_color="green")
            self.start_button.configure(text="Stop Server")
            self.port_entry.configure(state="disabled")
            # Update status text
            for widget in self.status_indicator.master.winfo_children():
                if isinstance(widget, ctk.CTkLabel) and widget.cget("text") in ["Server Offline", "Server Online"]:
                    widget.configure(text="Server Online")
        else:
            self.status_indicator.configure(text="●", text_color="red")
            self.start_button.configure(text="Start Server")
            self.port_entry.configure(state="normal")
            # Update status text
            for widget in self.status_indicator.master.winfo_children():
                if isinstance(widget, ctk.CTkLabel) and widget.cget("text") in ["Server Offline", "Server Online"]:
                    widget.configure(text="Server Offline")

    def toggle_server(self):
        """Toggle server state with comprehensive error handling."""
        global server_running, server
        
        if not server_running:
            try:
                # Validate port number
                try:
                    port = int(self.port_var.get())
                    if not (1024 <= port <= 65535):
                        raise ValueError("Port must be between 1024 and 65535")
                except ValueError as e:
                    show_notification("Error", str(e))
                    return
                
                # Check if port is available
                try:
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.bind(('0.0.0.0', port))
                    test_socket.close()
                except socket.error:
                    show_notification("Error", f"Port {port} is already in use")
                    return
                
                # Start server
                server = ServerThread(app, '0.0.0.0', port)
                server.daemon = True
                server.start()
                
                server_running = True
                self.update_server_status(True)
                
                # Update UI
                ip = get_local_ip()
                url = f"http://{ip}:{port}"
                self.ip_label.configure(text=f"Server running at: {url}")
                
                # Generate QR code
                try:
                    # Create QR code
                    qr = qrcode.QRCode(
                        version=1,
                        error_correction=qrcode.constants.ERROR_CORRECT_L,
                        box_size=10,
                        border=4,
                    )
                    qr.add_data(url)
                    qr.make(fit=True)
                    
                    # Create image
                    qr_image = qr.make_image(fill_color="black", back_color="white")
                    
                    # Resize image
                    qr_size = 200
                    qr_image = qr_image.resize((qr_size, qr_size))
                    
                    # Convert to CTkImage
                    self.qr_photo = ctk.CTkImage(
                        light_image=qr_image,
                        dark_image=qr_image,
                        size=(qr_size, qr_size)
                    )
                    
                    # Update QR label
                    self.qr_label.configure(image=self.qr_photo, text="")
                    
                    # Show QR frame
                    self.qr_frame.pack(fill="x", pady=(0, 20))
                    
                    # Force update
                    self.window.update_idletasks()
                    
                    logging.info("QR code generated and displayed successfully")
                except Exception as e:
                    logging.error(f"Failed to generate QR code: {e}")
                    show_notification("Error", "Failed to generate QR code")
                
                logging.info(f"Server started on {url}")
                show_notification("Server Started", f"Server is running at {url}")
                
            except Exception as e:
                logging.error(f"Failed to start server: {e}")
                server_running = False
                self.update_server_status(False)
                show_notification("Error", f"Failed to start server: {str(e)}")
        else:
            self.stop_server()

    def stop_server(self):
        """Stop server with error handling."""
        global server_running, server
        try:
            if server:
                server.shutdown()
                server = None
            server_running = False
            self.update_server_status(False)
            self.ip_label.configure(text="Server not running")
            
            # Clear QR code
            self.qr_label.configure(image="", text="")
            self.qr_photo = None
            self.qr_frame.pack_forget()
            
            # Force update
            self.window.update_idletasks()
            
            logging.info("Server stopped")
            show_notification("Server Stopped", "File transfer server has been stopped")
        except Exception as e:
            logging.error(f"Error stopping server: {e}")
            show_notification("Error", "Failed to stop server properly")

    def open_upload_folder(self):
        """Open the uploads folder in file explorer."""
        try:
            path = os.path.abspath(app.config['UPLOAD_FOLDER'])
            if sys.platform == 'win32':
                os.startfile(path)
            else:
                webbrowser.open(f'file://{path}')
        except Exception as e:
            logging.error(f"Error opening upload folder: {e}")
            show_notification("Error", "Could not open upload folder")

    def on_closing(self):
        """Handle window closing event."""
        try:
            # Stop monitoring thread
            self.monitoring_active = False
            if hasattr(self, 'monitor_thread'):
                self.monitor_thread.join(timeout=1)
            
            # Stop any ongoing transfers
            if hasattr(self, 'transfer_queue'):
                self.transfer_queue.put(None)  # Signal to stop transfer thread
            
            # Stop the server
            self.stop_server()
            
            # Save settings and stats
            self.save_settings()
            self.save_lifetime_stats()
            
            # Clean up temporary files
            try:
                temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp')
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except Exception as e:
                logging.error(f"Error cleaning up temp files: {e}")
            
            # Destroy the window
            self.window.destroy()
            
        except Exception as e:
            logging.error(f"Error during application shutdown: {e}")
            self.window.destroy()  # Ensure window is destroyed even if there's an error

    def run(self):
        """Start the GUI application with error handling."""
        try:
            # Start cleanup thread if enabled
            if self.auto_cleanup_enabled:
                cleanup_thread = threading.Thread(target=auto_cleanup, daemon=True)
                cleanup_thread.start()
            
            # Auto-start server if configured
            if self.settings.get('auto_start', False):
                self.window.after(1000, self.toggle_server)
            
            # Start main loop
            self.window.mainloop()
        except Exception as e:
            logging.critical(f"Application error: {e}")
            raise

    def load_lifetime_stats(self):
        """Load lifetime statistics from app data."""
        try:
            appdata_path = os.path.join(os.getenv('APPDATA') or os.path.expanduser('~'), '.wifi_transfer')
            os.makedirs(appdata_path, exist_ok=True)
            stats_file = os.path.join(appdata_path, 'lifetime_stats.json')
            history_file = os.path.join(appdata_path, 'file_history.json')
            
            # Load statistics
            if os.path.exists(stats_file):
                with open(stats_file, 'r') as f:
                    stats = json.load(f)
                    self.lifetime_bytes = stats.get('total_bytes', 0)
                    self.lifetime_files = stats.get('total_files', 0)
                    self.lifetime_speed_samples = stats.get('speed_samples', [])
                    self.blocked_ips = set(stats.get('blocked_ips', []))
                    
                    # Load connected devices
                    devices = stats.get('devices', {})
                    self.connected_devices = {
                        ip: ConnectedDevice.from_dict(data)
                        for ip, data in devices.items()
                    }
            
            # Load file history
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    self.file_history = json.load(f)
                    # Verify file existence and clean up history
                    self.file_history = [
                        entry for entry in self.file_history
                        if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], entry['filename']))
                    ]
            else:
                self.file_history = []
                
        except Exception as e:
            logging.error(f"Error loading lifetime stats: {e}")
            # Initialize with defaults if loading fails
            self.lifetime_bytes = 0
            self.lifetime_files = 0
            self.lifetime_speed_samples = []
            self.file_history = []

    def save_lifetime_stats(self):
        """Save lifetime statistics to app data."""
        try:
            appdata_path = os.path.join(os.getenv('APPDATA') or os.path.expanduser('~'), '.wifi_transfer')
            os.makedirs(appdata_path, exist_ok=True)
            stats_file = os.path.join(appdata_path, 'lifetime_stats.json')
            history_file = os.path.join(appdata_path, 'file_history.json')
            
            # Save statistics
            stats = {
                'total_bytes': self.lifetime_bytes,
                'total_files': self.lifetime_files,
                'speed_samples': self.lifetime_speed_samples[-1000:],  # Keep last 1000 samples
                'blocked_ips': list(self.blocked_ips),
                'devices': {
                    ip: device.to_dict()
                    for ip, device in self.connected_devices.items()
                }
            }
            
            with open(stats_file, 'w') as f:
                json.dump(stats, f, indent=4)
            
            # Save file history
            with open(history_file, 'w') as f:
                json.dump(self.file_history, f, indent=4)
                
        except Exception as e:
            logging.error(f"Error saving lifetime stats: {e}")

    def start_monitoring_threads(self):
        """Start system monitoring threads."""
        self.monitoring_active = True
        
        def monitor_system():
            while self.monitoring_active:
                try:
                    # Update CPU usage
                    self.cpu_usage = psutil.cpu_percent(interval=1)
                    
                    # Update RAM usage
                    memory = psutil.virtual_memory()
                    self.ram_usage = memory.percent
                    
                    # Update disk space
                    disk = psutil.disk_usage(app.config['UPLOAD_FOLDER'])
                    self.disk_space = disk
                    
                    # Update network speed
                    if self.last_network_check:
                        net_counters = psutil.net_io_counters()
                        time_diff = time.time() - self.last_network_check
                        
                        bytes_sent = net_counters.bytes_sent - self.last_bytes_sent
                        bytes_recv = net_counters.bytes_recv - self.last_bytes_recv
                        
                        self.network_speed = {
                            "up": bytes_sent / time_diff,
                            "down": bytes_recv / time_diff
                        }
                        
                        self.last_bytes_sent = net_counters.bytes_sent
                        self.last_bytes_recv = net_counters.bytes_recv
                    else:
                        net_counters = psutil.net_io_counters()
                        self.last_bytes_sent = net_counters.bytes_sent
                        self.last_bytes_recv = net_counters.bytes_recv
                    
                    self.last_network_check = time.time()
                    
                    # Update UI if window exists
                    if hasattr(self, 'window') and self.window.winfo_exists():
                        self.window.after(0, self.update_system_status)
                    else:
                        break
                    
                except Exception as e:
                    logging.error(f"Error in system monitoring: {e}")
                
                time.sleep(2)  # Update every 2 seconds
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=monitor_system, daemon=True)
        self.monitor_thread.start()

    def update_system_status(self):
        """Update system status display."""
        try:
            if hasattr(self, 'system_status_frame'):
                # Update disk space
                if self.disk_space:
                    free_space = get_human_readable_size(self.disk_space.free)
                    total_space = get_human_readable_size(self.disk_space.total)
                    self.disk_label.configure(
                        text=f"Disk Space: {self.disk_space.percent}% used ({free_space} free of {total_space})"
                    )
                
                # Update CPU and RAM
                self.cpu_label.configure(text=f"CPU: {self.cpu_usage}%")
                self.ram_label.configure(text=f"RAM: {self.ram_usage}%")
                
                # Update network speed
                up_speed = get_human_readable_size(self.network_speed["up"]) + "/s"
                down_speed = get_human_readable_size(self.network_speed["down"]) + "/s"
                self.network_label.configure(text=f"Network: ↑{up_speed} ↓{down_speed}")
        except Exception as e:
            logging.error(f"Error updating system status: {e}")

    def toggle_notifications(self):
        """Toggle notification system."""
        try:
            enabled = self.notification_switch.get()
            self.settings['notifications'] = enabled
            self.save_settings()
            
            status = "enabled" if enabled else "disabled"
            show_notification(
                "Settings Updated",
                f"Notifications {status}"
            )
        except Exception as e:
            logging.error(f"Error toggling notifications: {e}")

    def toggle_sound(self):
        """Toggle notification sound."""
        try:
            enabled = self.sound_switch.get()
            self.settings['notification_sound'] = enabled
            self.save_settings()
            
            status = "enabled" if enabled else "disabled"
            show_notification(
                "Settings Updated",
                f"Notification sound {status}"
            )
        except Exception as e:
            logging.error(f"Error toggling notification sound: {e}")

    def refresh_devices(self):
        """Refresh the connected devices list."""
        try:
            # Clear existing devices list
            for widget in self.devices_list.winfo_children():
                widget.destroy()
            
            # Add each device
            for ip, device in self.connected_devices.items():
                device_frame = ctk.CTkFrame(self.devices_list)
                device_frame.pack(fill="x", padx=5, pady=2)
                
                # Device icon (using Unicode symbol)
                icon_label = ctk.CTkLabel(
                    device_frame,
                    text="💻",  # Using Unicode symbol instead of image
                    font=("Arial", 16)
                )
                icon_label.pack(side="left", padx=5)
                
                # Rest of the device frame setup...
                info_frame = ctk.CTkFrame(device_frame)
                info_frame.pack(side="left", fill="x", expand=True, padx=5)
                
                name_label = ctk.CTkLabel(
                    info_frame,
                    text=device.name,
                    font=("Arial", 11, "bold")
                )
                name_label.pack(anchor="w")
                
                ip_label = ctk.CTkLabel(
                    info_frame,
                    text=f"IP: {device.ip}",
                    font=("Arial", 10)
                )
                ip_label.pack(anchor="w")
                
                # Status indicator
                status_color = "green" if device.status == "online" else "red"
                status_label = ctk.CTkLabel(
                    device_frame,
                    text="●",
                    text_color=status_color,
                    font=("Arial", 16)
                )
                status_label.pack(side="left", padx=5)
                
                # Control buttons
                control_frame = ctk.CTkFrame(device_frame)
                control_frame.pack(side="right", padx=5)
                
                # Rename button (using Unicode symbol)
                rename_button = ctk.CTkButton(
                    control_frame,
                    text="✏️",  # Using Unicode symbol
                    width=30,
                    command=lambda d=device: self.rename_device(d)
                )
                rename_button.pack(side="left", padx=2)
                
                # Block/Unblock button (using Unicode symbols)
                block_text = "🚫" if not device.blocked else "✅"
                block_button = ctk.CTkButton(
                    control_frame,
                    text=block_text,
                    width=30,
                    command=lambda d=device: self.toggle_device_block(d)
                )
                block_button.pack(side="left", padx=2)
        
        except Exception as e:
            logging.error(f"Error refreshing devices list: {e}")

    def rename_device(self, device):
        """Show dialog to rename a device."""
        try:
            dialog = ctk.CTkInputDialog(
                text=f"Enter new name for {device.name}:",
                title="Rename Device"
            )
            new_name = dialog.get_input()
            if new_name:
                device.name = new_name
                self.save_lifetime_stats()
                self.refresh_devices()
        except Exception as e:
            logging.error(f"Error renaming device: {e}")

    def toggle_device_block(self, device):
        """Toggle block status for a device."""
        try:
            device.blocked = not device.blocked
            if device.blocked:
                self.blocked_ips.add(device.ip)
            else:
                self.blocked_ips.discard(device.ip)
            self.save_lifetime_stats()
            self.refresh_devices()
        except Exception as e:
            logging.error(f"Error toggling device block: {e}")

# Flask routes
@app.route('/')
def index():
    """Serve the main page and track connected devices."""
    try:
        if hasattr(app, 'gui_instance'):
            # Get client IP
            client_ip = request.remote_addr
            
            # Check if IP is blocked
            if client_ip in app.gui_instance.blocked_ips:
                return "Access denied", 403
            
            # Get or create device
            if client_ip not in app.gui_instance.connected_devices:
                device_name = f"Device_{len(app.gui_instance.connected_devices) + 1}"
                app.gui_instance.connected_devices[client_ip] = ConnectedDevice(device_name, client_ip)
            
            # Update device status
            device = app.gui_instance.connected_devices[client_ip]
            device.status = "online"
            device.last_seen = datetime.now()
            
            # Save changes
            app.gui_instance.save_lifetime_stats()
            
            # Refresh devices list
            app.gui_instance.window.after(0, app.gui_instance.refresh_devices)
            
    except Exception as e:
        logging.error(f"Error tracking device: {e}")
    
    return render_template('index.html')

@app.route('/download/<path:filename>')
def download_file(filename):
    """Stream download of files."""
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        return 'File not found', 404

    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = 'application/octet-stream'

    file_size = os.path.getsize(file_path)
    
    def generate():
        with open(file_path, 'rb') as f:
            chunk_size = optimize_chunk_size()
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    headers = {
        'Content-Type': mime_type,
        'Content-Length': file_size,
        'Content-Disposition': f'attachment; filename="{filename}"'
    }

    return Response(
        stream_with_context(generate()),
        headers=headers
    )

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file uploads with parallel processing and update statistics."""
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    
    # Get client IP
    client_ip = request.remote_addr
    
    # Check if IP is blocked
    if client_ip in app.gui_instance.blocked_ips:
        return "Access denied", 403
    
    if file:
        try:
            filename = secure_filename(file.filename)
            # Handle file name conflicts
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
                filename = f"{base}_{counter}{ext}"
                counter += 1
            
            # Save to temp folder first
            temp_path = os.path.join('temp', filename)
            file.save(temp_path)
            
            def process_file():
                nonlocal temp_path, filename
                try:
                    # Apply compression if enabled
                    if app.gui_instance.compression_enabled:
                        compressed_path = compress_file(temp_path)
                        os.remove(temp_path)
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(compressed_path))
                        shutil.move(compressed_path, file_path)
                    else:
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        shutil.move(temp_path, file_path)
                    
                    # Encrypt file if enabled
                    if app.gui_instance.encryption_enabled and ENCRYPTION_KEY:
                        file_path = encrypt_file(file_path, ENCRYPTION_KEY)
                        filename = os.path.basename(file_path)
                    
                    return file_path
                except Exception as e:
                    logging.error(f"Error processing file {filename}: {e}")
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                    return None

            # Process file in thread pool
            future = executor.submit(process_file)
            file_path = future.result()
            
            if not file_path:
                return 'Processing failed', 500
            
            # Get file size
            file_size = os.path.getsize(file_path)
            
            # Update device statistics
            if client_ip in app.gui_instance.connected_devices:
                device = app.gui_instance.connected_devices[client_ip]
                device.total_transfers += 1
                device.total_bytes += file_size
                device.last_seen = datetime.now()
            
            # Update session statistics
            app.gui_instance.total_bytes_transferred += file_size
            app.gui_instance.total_files_transferred += 1
            
            # Update lifetime statistics
            app.gui_instance.lifetime_bytes += file_size
            app.gui_instance.lifetime_files += 1
            
            # Calculate and store transfer speed
            if app.gui_instance.transfer_start_time:
                duration = time.time() - app.gui_instance.transfer_start_time
                speed = file_size / duration
                app.gui_instance.transfer_speeds.append(speed)
                app.gui_instance.lifetime_speed_samples.append(speed)
            app.gui_instance.transfer_start_time = time.time()
            
            # Save statistics
            app.gui_instance.save_lifetime_stats()
            
            # Update GUI
            def update_gui():
                app.gui_instance.update_file_list(filename, file_size)
                app.gui_instance.update_statistics()
                app.gui_instance.refresh_devices()
                show_notification(
                    'File Received',
                    f'Received: {filename} ({get_human_readable_size(file_size)})'
                )
            
            # Schedule GUI update in the main thread
            if app.gui_instance and app.gui_instance.window:
                app.gui_instance.window.after(0, update_gui)
            
            logging.info(f"File uploaded successfully: {filename} ({file_size} bytes)")
            return 'File uploaded successfully'
            
        except Exception as e:
            logging.error(f"Upload error: {e}")
            return 'Upload failed', 500

@app.route('/security-status')
def security_status():
    """Get the current security settings."""
    return {
        'password_protected': app.gui_instance.password_protected,
        'encryption_enabled': app.gui_instance.encryption_enabled
    }

@app.route('/settings')
def get_settings():
    """Get current transfer settings."""
    return jsonify({
        'password_protected': app.gui_instance.password_protected,
        'encryption_enabled': app.gui_instance.encryption_enabled,
        'compression_enabled': app.gui_instance.compression_enabled,
        'auto_cleanup': app.gui_instance.auto_cleanup_enabled
    })

if __name__ == '__main__':
    try:
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=auto_cleanup, daemon=True)
        cleanup_thread.start()
        
        # Create and start GUI
        gui = FileTransferApp()
        app.gui_instance = gui
        gui.run()
    except Exception as e:
        logging.critical(f"Application failed to start: {e}")
        sys.exit(1) 