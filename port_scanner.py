import socket
import threading
import queue
import csv
import json

port_queue = queue.Queue()
open_ports = {}

# Common port to service mapping
port_services = {
    22: "SSH",
    80: "HTTP",
    135: "MS RPC",
    139: "NetBIOS",
    445: "SMB",
    902: "VMware",
    912: "VMware Authentication Daemon",
    3306: "MySQL",
    3389: "RDP"
}

# Scan a single port and grab banner
def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        
        if result == 0:
            banner = grab_banner(sock)
            service = port_services.get(port, "Unknown Service")
            open_ports[port] = {
                "service": service,
                "banner": banner
            }
            print(f"[+] Port {port} is OPEN on {target} - Service: {service} - {banner}")
        
        sock.close()
    
    except Exception as e:
        pass

# Grab banner from open port
def grab_banner(sock):
    try:
        sock.send(b"Hello\r\n")
        banner = sock.recv(1024).decode().strip()
        return banner if banner else "No Response"
    except:
        return "No Response"

# Worker threads to pull from queue and scan ports
def worker(target):
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(target, port)
        port_queue.task_done()

# Save results to CSV
def save_to_csv(target):
    with open(f"scan_results_{target}.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Port", "Service", "Banner"])
        for port, data in open_ports.items():
            writer.writerow([port, data['service'], data['banner']])
    print(f"\n[INFO] Scan results saved to scan_results_{target}.csv")

# Save results to JSON
def save_to_json(target):
    with open(f"scan_results_{target}.json", "w") as jsonfile:
        json.dump(open_ports, jsonfile, indent=4)
    print(f"[INFO] Scan results saved to scan_results_{target}.json")

# Main function to manage threading and initiate scan
def main():
    target = input("Enter target IP: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    threads = int(input("Enter number of threads: "))

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    print(f"\n[INFO] Scanning {target} from port {start_port} to {end_port}...\n")

    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(target,))
        thread.start()

    port_queue.join()

    print("\n[INFO] Scan complete.")
    if open_ports:
        for port, data in open_ports.items():
            print(f"Port {port}: {data['service']} - {data['banner']}")
        
        save_to_csv(target)
        save_to_json(target)
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()
