import subprocess
import re
import platform

def scan_wifi_networks():
    os_type = platform.system()
    
    if os_type == "Linux" or os_type == "Darwin":  # Para Linux e macOS
        try:
            result = subprocess.check_output(['iwlist', 'wlan0', 'scan'], universal_newlines=True)
            networks = re.findall(r'Cell \d+ - Address: (\S+).*?ESSID:"(.*?)".*?Quality=(\d+/\d+)', result, re.S)
        except subprocess.CalledProcessError:
            print("Erro ao escanear redes Wi-Fi.")
            return None

    elif os_type == "Windows":  # Para Windows
        try:
            result = subprocess.check_output(['netsh', 'wlan', 'show', 'network', 'mode=Bssid'], universal_newlines=True)
            networks = re.findall(r'SSID (\d+).*?\n.*?BSSID 1.*?: (\S+).*?\n.*?Sinal.*?: (\d+)%', result, re.S)
        except subprocess.CalledProcessError:
            print("Erro ao escanear redes Wi-Fi no Windows.")
            return None
    
    else:
        print(f"Sistema Operacional {os_type} não suportado para escaneamento Wi-Fi.")
        return None
    
    if not networks:
        print("Nenhuma rede Wi-Fi encontrada.")
        return None

    wifi_list = []
    # Exibe todas as redes encontradas
    print("Redes Wi-Fi Próximas:")
    for idx, network in enumerate(networks):
        if os_type == "Windows":
            ssid, bssid, signal_strength = network
            print(f"{idx + 1}. SSID: {ssid}, BSSID: {bssid}, Sinal: {signal_strength}%")
        else:
            bssid, ssid, quality = network
            print(f"{idx + 1}. SSID: {ssid}, BSSID: {bssid}, Qualidade: {quality}")
        
        wifi_list.append((ssid, bssid))
    
    return wifi_list

def main():
    wifi_networks = scan_wifi_networks()
    
    if wifi_networks:
        choice = int(input("Escolha uma rede Wi-Fi para mais informações: ")) - 1
        
        if 0 <= choice < len(wifi_networks):
            ssid, bssid = wifi_networks[choice]
            print(f"Você escolheu: SSID: {ssid}, BSSID: {bssid}")
        else:
            print("Escolha inválida.")
    else:
        print("Nenhuma rede Wi-Fi disponível.")

if __name__ == "__main__":
    main()
