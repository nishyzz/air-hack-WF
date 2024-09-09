import subprocess
import scapy.all as scapy
import re

def list_wifi_networks():
    networks = []
    try:
        output = subprocess.check_output(["nmcli", "-f", "SSID", "device", "wifi", "list"], universal_newlines=True)
        for line in output.splitlines()[1:]:
            networks.append(line.strip())
    except subprocess.CalledProcessError as e:
        print(f"Failed to list Wi-Fi networks: {e}")
    return networks

def get_network_details(ssid):
    try:
        # Get network details using nmcli
        output = subprocess.check_output(["nmcli", "-f", "IP4.ADDRESS", "connection", "show", ssid], universal_newlines=True)
        ip_range = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', output)
        if ip_range:
            return ip_range.group(0)
    except subprocess.CalledProcessError as e:
        print(f"Failed to get network details: {e}")
    return None

def scan_network(ip_range):
    print("Scanning network for devices...")
    devices = []
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    for element in answered_list:
        device_info = {
            "IP": element[1].psrc,
            "MAC": element[1].hwsrc
        }
        devices.append(device_info)
    
    return devices

def get_device_info(ip):
    try:
        output = subprocess.check_output(["arp", "-a"], universal_newlines=True)
        for line in output.splitlines():
            if ip in line:
                mac = re.findall(r"([0-9a-fA-F:]{17})", line)
                if mac:
                    return {"IP": ip, "MAC": mac[0]}
    except subprocess.CalledProcessError as e:
        print(f"Failed to get device info: {e}")
    return {"IP": ip, "MAC": "Unknown"}

def main():
    print("Available Wi-Fi Networks:")
    networks = list_wifi_networks()
    
    if not networks:
        print("No Wi-Fi networks found.")
        return
    
    for idx, network in enumerate(networks):
        print(f"{idx + 1}. {network}")
    
    choice = int(input("Select the network to scan (by number): ")) - 1
    if choice < 0 or choice >= len(networks):
        print("Invalid choice.")
        return
    
    ssid = networks[choice]
    print(f"Scanning network: {ssid}")
    
    ip_range = get_network_details(ssid)
    if not ip_range:
        print("Could not determine IP range for the selected network.")
        return
    
    print(f"IP Range for network {ssid}: {ip_range}")
    
    devices = scan_network(ip_range)
    
    if devices:
        for device in devices:
            info = get_device_info(device["IP"])
            print(f"Device found - IP: {info['IP']}, MAC: {info['MAC']}")
    else:
        print("No devices found on the network.")

if __name__ == "__main__":
    main()
