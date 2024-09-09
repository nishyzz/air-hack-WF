import os
import platform
import subprocess
import time

try:
    import pywifi
except ImportError:
    pywifi = None  # pywifi será usado apenas no Windows

# Função para escanear redes no Linux
def scan_wifi_linux():
    try:
        result = subprocess.check_output(['nmcli', '-t', '-f', 'SSID', 'dev', 'wifi'], universal_newlines=True)
        networks = result.strip().split('\n')
        if networks:
            print("Redes Wi-Fi Próximas (Linux):")
            for idx, network in enumerate(networks, 1):
                print(f"{idx}. SSID: {network}")
        else:
            print("Nenhuma rede Wi-Fi encontrada no Linux.")
    except Exception as e:
        print(f"Erro ao escanear redes Wi-Fi no Linux: {e}")

# Função para escanear redes no Termux (usando arp-scan)
def scan_wifi_termux():
    try:
        result = subprocess.check_output(['arp-scan', '--localnet'], universal_newlines=True)
        print("Redes Wi-Fi Próximas (Termux):")
        print(result)
    except Exception as e:
        print(f"Erro ao escanear redes Wi-Fi no Termux: {e}")

# Função para escanear redes no Windows (usando pywifi)
def scan_wifi_windows():
    if not pywifi:
        print("pywifi não está instalado.")
        return
    
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]

    iface.scan()  # Inicia a varredura
    time.sleep(3)  # Aguarda a varredura ser concluída
    scan_results = iface.scan_results()

    if not scan_results:
        print("Nenhuma rede Wi-Fi encontrada no Windows.")
        return

    wifi_list = []
    print("Redes Wi-Fi Próximas (Windows):")
    for idx, network in enumerate(scan_results):
        ssid = network.ssid
        bssid = network.bssid
        signal = network.signal
        print(f"{idx + 1}. SSID: {ssid}, BSSID: {bssid}, Sinal: {signal}")
        wifi_list.append((ssid, bssid))
    
    return wifi_list

# Menu principal
def main():
    system_os = platform.system().lower()

    if system_os == 'linux':
        if 'termux' in os.environ.get('PREFIX', ''):
            print("Executando no Termux.")
            scan_wifi_termux()
        else:
            print("Executando no Linux.")
            scan_wifi_linux()

    elif system_os == 'windows':
        print("Executando no Windows.")
        scan_wifi_windows()

    else:
        print("Sistema Operacional não suportado.")

if __name__ == "__main__":
    main()
