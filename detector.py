#!/usr/bin/python3
#
#--------------------------------------------------------------------------------------------------------------------------
# Pembuat: Rofi (Fixploit03)
# Github: https://github.com/fixploit03/deauther
# Copyright (c) 2025 - Rofi (Fixploit03)
#--------------------------------------------------------------------------------------------------------------------------
# DISCLAIMER:
#
# Program ini dibuat semata-mata untuk tujuan edukasi dan pembelajaran tentang keamanan jaringan nirkabel (Wi-Fi).
# Penggunaan program ini harus dilakukan hanya pada jaringan atau perangkat yang Anda miliki atau memiliki izin eksplisit
# dari pemiliknya untuk menguji keamanannya. Penggunaan program ini untuk tujuan ilegal, seperti mengganggu,
# menyusup, atau merusak jaringan tanpa izin, adalah melanggar hukum di banyak yurisdiksi dan dapat mengakibatkan
# konsekuensi hukum yang serius, termasuk denda atau penjara.
#
# Pembuat (Rofi/Fixploit03) tidak bertanggung jawab atas segala bentuk penyalahgunaan atau kerusakan
# yang disebabkan oleh penggunaan program ini. Anda, sebagai pengguna, bertanggung jawab penuh atas tindakan Anda
# sendiri dan harus mematuhi hukum serta peraturan yang berlaku di wilayah Anda.
#
# Program ini dirancang untuk membantu memahami cara kerja serangan deauthentication dalam lingkungan yang terkendali
# dan legal, seperti laboratorium keamanan siber atau pengujian penetrasi yang diizinkan. Kami sangat menyarankan
# agar Anda mempelajari etika hacking dan hukum terkait sebelum menggunakan program ini. Jangan gunakan program ini untuk
# tujuan jahat atau tanpa persetujuan yang sah dari pihak yang berwenang.
#
# Dengan menggunakan program ini, Anda menyatakan bahwa Anda memahami risiko, tanggung jawab, dan batasan hukumnya,
# serta setuju untuk menggunakannya hanya dalam konteks yang sah dan etis untuk kepentingan pendidikan atau
# pengujian keamanan yang diizinkan.
#--------------------------------------------------------------------------------------------------------------------------

import sys
import time
import os
import signal
import argparse
from scapy.all import *
from termcolor import colored

# Global flag to stop scanning
stop_scanning = False

# Dictionary to map BSSID to SSID
bssid_to_ssid = {}

def signal_handler(sig, frame):
    """Handle Ctrl+C to stop the program gracefully"""
    global stop_scanning
    time_str = colored(get_current_time(), 'cyan')
    print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + 
          colored("Ctrl+C pressed. Stopping deauthentication attack scan...", 'white'))
    stop_scanning = True
    sys.exit(0)

def get_current_time():
    """Return the current time in HH:MM:SS format"""
    return time.strftime("%H:%M:%S")

def check_root():
    """Verify if the program is running with root privileges"""
    if os.geteuid() != 0:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + 
              colored("This program requires root privileges!", 'white'))
        sys.exit(1)

def check_interface_exists(interface):
    """Check if the specified network interface exists"""
    interfaces = os.listdir("/sys/class/net/")
    if interface not in interfaces:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + 
              colored(f"Network interface '{interface}' not found!", 'white'))
        sys.exit(1)

def check_interface_mode(interface):
    """Ensure the network interface is in monitor mode"""
    try:
        result = os.popen(f"iwconfig {interface}").read()
        if "Mode:Monitor" not in result:
            time_str = colored(get_current_time(), 'cyan')
            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + 
                  colored("Network interface must be in monitor mode!", 'white'))
            sys.exit(1)
    except Exception as e:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + 
              colored(f"Error checking interface mode: {e}", 'white'))
        sys.exit(1)

def set_channel(interface, channel):
    """Set the network interface to a specific channel"""
    try:
        os.system(f"sudo iwconfig {interface} channel {channel}")
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + 
              colored(f"Switched to channel {channel}", 'white'))
    except Exception as e:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + 
              colored(f"Failed to switch to channel {channel}: {e}", 'white'))
        sys.exit(1)

def collect_ssid(interface, timeout=2):
    """Collect SSIDs from beacon frames to map BSSID to SSID"""
    def beacon_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr2
            if bssid not in bssid_to_ssid:
                ssid = pkt.info.decode('utf-8', errors='ignore') if pkt.info else "Hidden SSID"
                bssid_to_ssid[bssid] = ssid
                time_str = colored(get_current_time(), 'cyan')
                print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + 
                      colored(f"Found SSID: {ssid} for BSSID: {bssid}", 'white'))

    sniff(iface=interface, prn=beacon_handler, timeout=timeout, store=0)

def scan_deauthentication_attack(interface, channel, scan_time):
    """Scan for deauthentication attack packets on a specific channel"""
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Deauth):
            time_str = colored(get_current_time(), 'cyan')
            src = pkt.addr2 if pkt.addr2 else "Unknown"  # Source MAC (attacker)
            dst = pkt.addr1 if pkt.addr1 else "Unknown"  # Destination MAC (client or broadcast)
            bssid = pkt.addr3 if pkt.addr3 else None     # BSSID of the AP

            # Retrieve target SSID based on BSSID
            ssid = bssid_to_ssid.get(bssid, "Unknown SSID") if bssid else "Unknown SSID"
            
            # Format target string
            if dst == "ff:ff:ff:ff:ff:ff":
                target_str = f"{ssid} (Broadcast)"
            else:
                target_str = f"{ssid} (Client: {dst})"

            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("WARNING", 'yellow', attrs=['bold']) + colored("] ", 'white') + 
                  colored(f"Deauthentication attack detected on channel {channel}! Source: {src} -> Target: {target_str}", 'white'))

    # Collect SSID data before scanning for deauthentication packets
    collect_ssid(interface, timeout=2)  # 2 seconds to gather SSIDs
    sniff(iface=interface, prn=packet_handler, timeout=scan_time, stop_filter=lambda x: stop_scanning)

def monitor_channels(interface, channel=None, scan_time=5):
    """Monitor a specific channel or all channels (1-14) for deauthentication attacks"""
    time_str = colored(get_current_time(), 'cyan')
    if channel is not None:
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + 
              colored(f"Starting deauthentication attack scan on channel {channel} (duration: {scan_time} seconds)...", 'white'))
    else:
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + 
              colored(f"Starting deauthentication attack scan across all channels (1-14, duration: {scan_time} seconds per channel)...", 'white'))

    while not stop_scanning:
        if channel is not None:
            # Scan only the specified channel
            set_channel(interface, channel)
            scan_deauthentication_attack(interface, channel, scan_time)
        else:
            # Scan all channels (1-14)
            for ch in range(1, 15):
                if stop_scanning:
                    break
                set_channel(interface, ch)
                scan_deauthentication_attack(interface, ch, scan_time)

def main():
    """Main function to manage program execution"""
    signal.signal(signal.SIGINT, signal_handler)
    check_root()

    description = (
        "WiFi Deauthentication Attack Detector Program\n"
        "Author: Rofi (Fixploit03)\n"
        "GitHub: https://github.com/fixploit03/deauther\n"
        "Copyright (c) 2025 Rofi (Fixploit03). All rights reserved."
    )
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-i", "--interface", required=True, help="Network interface in monitor mode (e.g., wlan0)")
    parser.add_argument("-c", "--channel", type=int, default=None, help="Specific channel to scan (e.g., 6). If omitted, scans all channels 1-14")
    parser.add_argument("-s", "--scan-time", type=int, default=5, help="Scan duration per channel in seconds (default: 5)")

    args = parser.parse_args()

    # Validate channel if provided
    if args.channel is not None and (args.channel < 1 or args.channel > 14):
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + 
              colored("Channel must be between 1 and 14!", 'white'))
        sys.exit(1)

    # Validate scan duration
    if args.scan_time <= 0:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + 
              colored("Scan duration must be greater than 0 seconds!", 'white'))
        sys.exit(1)

    check_interface_exists(args.interface)
    check_interface_mode(args.interface)

    try:
        monitor_channels(args.interface, args.channel, args.scan_time)
    except Exception as e:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + 
              colored(f"Critical error during deauthentication attack scan: {e}", 'white'))
        sys.exit(1)

if __name__ == "__main__":
    main()
