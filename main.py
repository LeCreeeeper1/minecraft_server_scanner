import threading
import socket
import random
import os
import json
import ctypes
from queue import Queue
from mcstatus import JavaServer

MC_JSON = "servers.json"
SCAN_PORT = 25565
IP_TESTED = set()
DATA_BUFFER = []
BUFFER_LOCK = threading.Lock()
SCAN_QUEUE = Queue()
ANALYSIS_QUEUE = Queue()
PROCESSING_LOCK = threading.Lock()

INFINITE_MODE = False
TOTAL_IPS_TO_SCAN = 0  # Used for display


def generate_ip():
    base = random.choice(["51.38", "5.39", "95.216", "3.8", "13.48", "23.102"])
    return f"{base}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def tcp_ping(ip, port):
    try:
        conn = socket.create_connection((ip, port), timeout=0.3)
        conn.close()
        return True
    except:
        return False


def mcstatus_scan(ip, port):
    try:
        server = JavaServer.lookup(f"{ip}:{port}")
        status = server.status()
        version = status.version.name.lower()
        modloader = next((m for m in ["forge", "fabric", "quilt", "liteloader", "spigot", "paper", "bukkit"] if m in version), "vanilla")
        with BUFFER_LOCK:
            DATA_BUFFER.append({
                "ip": ip,
                "port": port,
                "version": status.version.name,
                "modloader": modloader,
                "players": status.players.online,
                "motd": str(status.description)
            })
        print(f"✅ {ip}:{port} - {modloader} - {status.players.online} players")
    except:
        pass


def save_results():
    if not DATA_BUFFER:
        return
    try:
        if os.path.exists(MC_JSON):
            with open(MC_JSON, "r") as f:
                data = json.load(f)
        else:
            data = []
        existing_ips = [e["ip"] for e in data]
        with BUFFER_LOCK:
            new_data = [entry for entry in DATA_BUFFER if entry["ip"] not in existing_ips]
            data.extend(new_data)
            DATA_BUFFER.clear()
        with open(MC_JSON, "w") as f:
            json.dump(data, f, indent=2)
    except:
        pass


def update_processing_file(ip=None, remove=False):
    processing_file = "processing.txt"
    try:
        with PROCESSING_LOCK:
            if remove:
                if os.path.exists(processing_file):
                    with open(processing_file, "r") as f:
                        lines = f.readlines()
                    with open(processing_file, "w") as f:
                        f.writelines(line for line in lines if line.strip() != ip)
            else:
                with open(processing_file, "a") as f:
                    f.write(f"{ip}\n")
    except Exception as e:
        print(f"Error updating processing.txt: {e}")


def scan_worker():
    while True:
        ip = SCAN_QUEUE.get()
        if ip is None:
            break

        if ip in IP_TESTED:
            SCAN_QUEUE.task_done()
            continue

        IP_TESTED.add(ip)
        try:
            if tcp_ping(ip, SCAN_PORT):
                mode = f"{len(IP_TESTED)}/{TOTAL_IPS_TO_SCAN}" if not INFINITE_MODE else "infinite mode"
                print(f"🟢 IP found {ip}:{SCAN_PORT} [{mode}]")
                update_processing_file(ip)
                if INFINITE_MODE:
                    ANALYSIS_QUEUE.put(ip)
        finally:
            SCAN_QUEUE.task_done()


def mcstatus_worker():
    while True:
        ip = ANALYSIS_QUEUE.get()
        if ip is None:
            break
        mcstatus_scan(ip, SCAN_PORT)
        ANALYSIS_QUEUE.task_done()


def analyze_processing_file():
    processing_file = "processing.txt"
    if not os.path.exists(processing_file):
        return
    with open(processing_file, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    for ip in ips:
        ANALYSIS_QUEUE.put(ip)

    ANALYSIS_QUEUE.join()
    save_results()

    # Clean the processing.txt after analysis
    try:
        with open(processing_file, "w") as f:
            f.write("")  # Empty file
    except Exception as e:
        print(f"Error clearing processing.txt: {e}")


def main():
    global INFINITE_MODE, TOTAL_IPS_TO_SCAN
    ctypes.windll.kernel32.SetThreadExecutionState(0x80000002)  # Prevent sleep mode

    num_ips = int(input("Enter the number of thousands of IPs to scan (0 for infinite): "))
    num_threads = int(input("Enter the number of threads (over 1000 may break console output): "))

    INFINITE_MODE = (num_ips == 0)
    if not INFINITE_MODE:
        num_ips *= 1000
        TOTAL_IPS_TO_SCAN = num_ips
    else:
        TOTAL_IPS_TO_SCAN = -1  # Not relevant in infinite mode

    print("🚀 Starting scan...")

    # Start mcstatus threads
    analysis_threads = []
    for _ in range(10):
        t = threading.Thread(target=mcstatus_worker)
        t.start()
        analysis_threads.append(t)

    # Start scan threads
    scan_threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=scan_worker)
        t.start()
        scan_threads.append(t)

    try:
        count = 0
        while INFINITE_MODE or count < num_ips:
            ip = generate_ip()
            SCAN_QUEUE.put(ip)
            count += 1
    except KeyboardInterrupt:
        print("🛑 Stopping scan...")

    SCAN_QUEUE.join()

    for _ in scan_threads:
        SCAN_QUEUE.put(None)
    for t in scan_threads:
        t.join()

    if not INFINITE_MODE:
        print("🔍 Starting full server analysis...")
        analyze_processing_file()

    for _ in analysis_threads:
        ANALYSIS_QUEUE.put(None)
    for t in analysis_threads:
        t.join()

    if not os.path.exists(MC_JSON) or os.path.getsize(MC_JSON) == 0:
        print("❌ No servers found! Try increasing the number of IPs.")
    else:
        print("✅ Scan and analysis complete. Results saved to servers.json.")


if __name__ == "__main__":
    main()
