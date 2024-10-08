                           Wifire
               (   Version 1.0   ) Release!!!
          +-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+
          |B|y| |S|h|e|i|k|h| |N|i|g|h|t|s|h|a|d|e|r|
          +-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+


Wifire: Automated Wi-Fi Scanner and Attacker 

Introduction

 Wifire is a Python-based tool that enables Wi-Fi network scanning, deauthentication attacks, and WPA/WPA2 handshake capture. It captures WPA/WPA2 handshakes and extracts hashes for further analysis.PrerequisitesBefore using Wifire, ensure the following prerequisites are met:

Operating
System: Linux-based system (Kali Linux preferred for Wi-Fi pentesting).

Python3: Ensure Python3 and Scapy library are installed:

sudo apt-get install python3-pippip3 install scapy

Wi-Fi Interface: Use a Wi-Fi adapter that supports monitor mode and packet injection.

Root Privileges: Run the script with root privileges (sudo).

How to Use

Step 1: Download the ScriptSave the Python script provided into a file, for example, wifire.py.

Step 2: Run the Script Use the following command to run the script, providing the required arguments:
sudo python3 wifire.py --interface <your_wifi_interface> [options]Required Argument--interface: The Wi-Fi interface you wish to use (e.g., wlan0).Optional Arguments--duration: Duration (in seconds) for the initial scanning phase. Default is 60 seconds.--output: Name of the .cap file where the captured handshakes will be stored. Default is handshake.cap.--hashfile: Name of the text file where the WPA/WPA2 hashes will be saved. Default is wpa_hash.txt.--deauth: Number of deauth packets to send per target. Default is 10.--capture_duration: Duration (in seconds) for capturing handshakes after the deauth attack. Default is 30 seconds.

Example Command:
sudo python3 wifire.py --interface wlan0 --duration 60 --output handshake.cap --hashfile wpa_hash.txt --deauth 20 --capture_duration 30

If failed to change interface to monitor mode and you did it manually use this command.
airmon-ng start wlan0
and run.
sudo python3 wifire.py --interface wlan0mon --duration 60 --output handshake.cap --hashfile wpa_hash.txt --deauth 20 --capture_duration 30

Walkthrough of the Process

Step 1: Scan for Access PointsOnce the script is started, it will scan for Wi-Fi networks within range for the specified duration. During the scan, it will list available APs (Access Points) along with their SSIDs and BSSIDs.

Step 2: Select Access Point After the scan completes, you'll be asked to select an Access Point (AP) by entering the corresponding number from the displayed list.

Step 3: Enter Target MAC AddressNext, enter the MAC address of the client device you want to deauthenticate from the selected Access Point. This can be obtained through various network monitoring tools or during the scan.

Step 4: Deauth Attack and Capture Handshakes The script will initiate a deauthentication attack on the selected AP and target client, disrupting their connection. Simultaneously, the script will capture WPA/WPA2 handshakes and save them in the .cap file specified.Step 5: Save WPA/WPA2 HashesAfter the attack, the script extracts the WPA/WPA2 handshake hash and saves it in the text file specified (wpa_hash.txt).

Output Files.cap File: Stores the captured WPA/WPA2 handshakes.txt File: Stores extracted WPA/WPA2 hashes from the handshakes for further analysis.

Notes

Legal Disclaimer: This tool is for educational purposes and should only be used on networks that you own or have permission to test Performance: Results may vary depending on the Wi-Fi adapter and its compatibility with monitor mode and packet injection.Further Use: Captured handshakes can be analyzed using hash-cracking tools like aircrack-ng or hashcat.
