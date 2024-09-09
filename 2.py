import subprocess
import re

def list_wifi_networks():
    # Termux não suporta nmcli, então listamos SSIDs manualmente
    # Para Termux, você pode usar o comando `iwgetid` para obter o SSID da rede conectada
    try:
        output = subprocess.check_output(["iwgetid", "-r"], universal_newlines=True).strip()
        return [output]
    except subprocess.CalledProcessError as e:
        print(f"Failed to list Wi-Fi networks: {e}")
        return []

def get_ip_range():
    try:
        # Utilize o comando ifconfig para obter o IP da interface de rede
        output = subprocess.check_output(["ifconfig"], universal_newlines=True)
        ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', output)
        if ip_match:
            ip = ip_match.group(1)
            # Inferir intervalo IP a partir do IP obtido
            return f"{ip}/24"
    except subprocess.CalledProcessError as e:
        print(f"Failed to get IP range: {e}")
    return None

def scan_network(ip_range):
    print("Scanning network for devices...")
    devices = []
    try:
        output = subprocess.check_output(["sudo", "arp-scan", "--interface=wlan0", "--localnet"], universal_newlines=True)
        for line in output.splitlines():
            if re.match(r'\d+\.\d+\.\d+\.\d+', line):
                parts = line.split()
                if len(parts) >= 2:
                    device_info = {
                        "IP": parts[0],
                        "MAC": parts[1]
                    }
                    devices.append(device_info)
    except subprocess.CalledProcessError as e:
        print(f"Failed to scan network: {e}")
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
    
    print(f"Connected to: {networks[0]}")
    
    ip_range = get_ip_range()
    if not ip_range:
        print("Could not determine IP range.")
        return
    
    print(f"IP Range for network: {ip_range}")
    
    devices = scan_network(ip_range)
    
    if devices:
        for device in devices:
            info = get_device_info(device["IP"])
            print(f"Device found - IP: {info['IP']}, MAC: {info['MAC']}")
    else:
        print("No devices found on the network.")

if __name__ == "__main__":
    main()
