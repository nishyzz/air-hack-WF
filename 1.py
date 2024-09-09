import socket
import threading

def check_port(ip, port, results):
    print(f"Checking port {port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = s.connect_ex((ip, port))
    if result == 0:
        results.append(port)
        print(f"Port {port} is open")
    else:
        print(f"Port {port} is closed or filtered")
    s.close()

def scan_ports(ip, start_port, end_port):
    results = []
    threads = []
    
    print(f"Scanning IP: {ip} from port {start_port} to {end_port}...")
    
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=check_port, args=(ip, port, results))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    return results

def main():
    while True:
        print("\nMenu:")
        print("1. Scan for open ports")
        print("2. Exit")
        
        choice = input("Enter your choice (1/2): ")
        
        if choice == '1':
            ip = input("Enter the IP address to scan: ")
            start_port = int(input("Enter the starting port number: "))
            end_port = int(input("Enter the ending port number: "))
            
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                print("Invalid port range. Please enter valid port numbers between 1 and 65535.")
                continue
            
            open_ports = scan_ports(ip, start_port, end_port)
            if open_ports:
                print(f"\nOpen ports on {ip}: {', '.join(map(str, open_ports))}")
            else:
                print(f"\nNo open ports found on {ip}.")
        
        elif choice == '2':
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please select 1 or 2.")

if __name__ == "__main__":
    main()
