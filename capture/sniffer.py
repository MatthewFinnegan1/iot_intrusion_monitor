from scapy.all import sniff, IP
from datetime import datetime
from detection.maliciousIPDetection import trim_csv
def is_noise_traffic(ip):
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.") or
        ip.startswith("224.") or  # multicast
        ip.startswith("239.") or
        ip == "255.255.255.255"
    )


def handle_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

        if not is_noise_traffic(dst):
            timestamp = datetime.now().isoformat()
            #print(f"[{timestamp}] {src} → {dst}")
            with open("data/traffic_log.csv", "a") as f:
                f.write(f"{timestamp},{src},{dst}\n")
                #trim_csv("data/traffic_log.csv", 10000)

def start_sniffing():
    print("Starting basic packet sniffer... (press Ctrl+C to stop)")
    sniff(filter="ip", prn=handle_packet, store=False)

if __name__ == "__main__":
    start_sniffing()