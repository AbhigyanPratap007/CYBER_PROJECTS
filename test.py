import socket
import threading
import queue
import csv
import json
import subprocess
import time

# Initialize global variables
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

# Scan a single port and grab the banner
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

# Worker thread to pull from queue and scan ports
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
    print(f"[INFO] Scan results saved to scan_results_{target}.csv")

# Save results to JSON
def save_to_json(target):
    with open(f"scan_results_{target}.json", "w") as jsonfile:
        json.dump(open_ports, jsonfile, indent=4)
    print(f"[INFO] Scan results saved to scan_results_{target}.json")

# Run Nmap and parse results for comparison
def run_nmap(target, start_port, end_port):
    print("\n[INFO] Running Nmap for comparison...\n")
    nmap_command = f"nmap -p {start_port}-{end_port} {target} -sV"
    result = subprocess.run(nmap_command, shell=True, capture_output=True, text=True)
    nmap_output = result.stdout

    nmap_ports = {}
    for line in nmap_output.split('\n'):
        if '/tcp' in line and 'open' in line:
            parts = line.split()
            port = int(parts[0].split('/')[0])
            service = parts[2] if len(parts) > 2 else 'Unknown'
            nmap_ports[port] = service

    if not nmap_ports:
        print("[WARNING] Nmap did not detect any open ports. Run as Administrator if necessary.")
    return nmap_ports

# Compare Nmap results with custom scanner
def compare_with_nmap(target, start_port, end_port):
    nmap_ports = run_nmap(target, start_port, end_port)
    matched = 0
    total = len(nmap_ports)

    for port, service in nmap_ports.items():
        if port in open_ports:
            matched += 1
        else:
            print(f"[INFO] Nmap found open port {port} - Missed by custom scanner")

    accuracy = (matched / total) * 100 if total > 0 else 0
    print(f"\n[INFO] Scan Comparison Complete: {matched}/{total} ports matched ({accuracy:.2f}% accuracy)\n")

# Main function to manage threading and initiate scan
def main():
    target = input("Enter target IP: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    threads = int(input("Enter number of threads: "))

    # Fill the queue with ports to scan
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    print(f"\n[INFO] Scanning {target} from port {start_port} to {end_port}...\n")

    start_time = time.time()

    # Start worker threads
    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(target,))
        thread.start()

    port_queue.join()  # Wait for all tasks to complete

    end_time = time.time()
    scan_duration = end_time - start_time
    efficiency = (end_port - start_port + 1) / scan_duration if scan_duration > 0 else 0

    print(f"\n[INFO] Scan complete in {scan_duration:.2f} seconds")
    print(f"[INFO] Efficiency: {efficiency:.2f} ports per second")

    if open_ports:
        for port, data in open_ports.items():
            print(f"Port {port}: {data['service']} - {data['banner']}")
        
        save_to_csv(target)
        save_to_json(target)
        compare_with_nmap(target, start_port, end_port)
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()
