from scapy.all import sniff, Ether, IP, TCP, UDP, Raw, Dot11
import binascii

def hex_to_text(hex_data):
    """Converte dados hexadecimais para texto legível."""
    try:
        bytes_data = bytes.fromhex(hex_data)
        text = bytes_data.decode('utf-8', errors='replace')
        return text
    except ValueError:
        return "Dados não convertíveis para texto."

def extract_ssid(packet):
    """Extrai o SSID de pacotes Wi-Fi."""
    if packet.haslayer(Dot11):
        dot11_layer = packet[Dot11]
        if dot11_layer.type == 0 and dot11_layer.subtype == 8:  # Beacon frame
            ssid = dot11_layer.info.decode('utf-8', errors='replace')
            return ssid
    return "SSID não disponível"

def packet_callback(packet):
    """Função de callback para exibir pacotes capturados com detalhes."""
    print("\nPacote Capturado:")
    
    # Exibir camada Ethernet
    if Ether in packet:
        eth_layer = packet[Ether]
        print(f"    Fonte MAC: {eth_layer.src}")
        print(f"    Destino MAC: {eth_layer.dst}")
        print(f"    Tipo: {eth_layer.type}")

    # Exibir camada IP
    if IP in packet:
        ip_layer = packet[IP]
        print(f"    Endereço IP de Origem: {ip_layer.src}")
        print(f"    Endereço IP de Destino: {ip_layer.dst}")
        print(f"    Protocolo: {ip_layer.proto}")
        print(f"    TTL: {ip_layer.ttl}")
        print(f"    Tamanho Total: {ip_layer.len}")

        # Exibir camada TCP ou UDP se presente
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"    Porta de Origem: {tcp_layer.sport}")
            print(f"    Porta de Destino: {tcp_layer.dport}")
            print(f"    Número de Sequência: {tcp_layer.seq}")
            print(f"    Número de Acknowledgment: {tcp_layer.ack}")
            print(f"    Flags: {tcp_layer.flags}")
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"    Porta de Origem: {udp_layer.sport}")
            print(f"    Porta de Destino: {udp_layer.dport}")

    # Exibir dados brutos
    if Raw in packet:
        raw_data = packet[Raw].load
        hex_data = binascii.hexlify(raw_data).decode('utf-8')
        print(f"    Dados Transmitidos (em hexadecimal): {hex_data}")
        text_data = hex_to_text(hex_data)
        print(f"    Dados Transmitidos (em texto): {text_data}")

    # Exibir SSID (para pacotes Wi-Fi)
    ssid = extract_ssid(packet)
    print(f"    SSID: {ssid}")

def main():
    """Captura pacotes de rede com filtro de IP e exibe informações detalhadas."""
    ip_filter = input("Digite o IP para filtrar (ou deixe em branco para capturar todos os pacotes): ")
    filter_str = f"ip host {ip_filter}" if ip_filter else "ip"
    print(f"Capturando pacotes com filtro: {filter_str}. Pressione Ctrl+C para parar.")
    sniff(prn=packet_callback, filter=filter_str, store=0)

if __name__ == "__main__":
    main()
