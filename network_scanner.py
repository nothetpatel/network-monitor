from scapy.all import ARP, Ether, srp
import sqlite3
from datetime import datetime
import os, time

def scan_network(network):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(packet, timeout=1, verbose=0)
    devices = []
    for response in answered:
        details = {"ip": response[1].psrc, "mac":  response[1].hwsrc}
        devices.append(details)
    return devices

def init_db():
    conn = sqlite3.connect("network.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS devices (ip TEXT, mac TEXT UNIQUE, last_seen TEXT)")
    conn.commit()
    conn.close()

def save_devices(devices):
    conn = sqlite3.connect("network.db")
    cursor = conn.cursor()
    
    for d in devices:
        currTime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        data = (d['ip'], d['mac'], currTime)

        cursor.execute("INSERT OR REPLACE INTO devices (ip, mac, last_seen) VALUES (?, ?, ?)", data)

    conn.commit()
    conn.close()

def detect_new_devices(devices):
    conn = sqlite3.connect("network.db")
    cursor = conn.cursor()

    for d in devices:
        cursor.execute("SELECT mac FROM devices WHERE mac = ?", (d['mac'],))
        result = cursor.fetchone()

        if result is None:
            print(f"NEW DEVICE DETECTED: IP: {d['ip']} MAC: {d['mac']}")

    conn.close()

# main code

init_db()

while True:
    os.system("clear")

    devices = scan_network("192.168.2.0/24")
    detect_new_devices(devices)
    save_devices(devices)

    for device in devices:
        print(f"IP: {device['ip']} MAC: {device['mac']}")
    

    print(f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    time.sleep(60)
