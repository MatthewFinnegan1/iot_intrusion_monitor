from capture.sniffer import start_sniffing
from detection.maliciousIPDetection import start_detecting
import threading

sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
sniffer_thread.start()

start_detecting()