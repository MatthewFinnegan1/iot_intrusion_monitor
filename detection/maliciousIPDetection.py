import requests
import os
import json
import csv
import time
import pandas as pd
from dataclasses import dataclass
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv('API_KEY')
url = 'https://api.abuseipdb.com/api/v2/check'

headers = {
    'Accept': 'application/json',
    'Key': API_KEY
}

HIGH_RISK_COUNTRIES = {
    "CN",  # China
    "RU",  # Russia
    "TR",  # Turkey
    "BR",  # Brazil
    "BD",  # Bangladesh
    "PK",  # Pakistan
    "IN",  # India
    "NP",  # Nepal
    "RO",  # Romania
    "AF",  # Afghanistan
}
def trim_csv(path : str, max_rows : int, has_header=False):
    if not os.path.exists(path):
        print(f"[!] File does not exist: {path}")
        return

    try:
        if has_header:
            df = pd.read_csv(path)
            if len(df) > max_rows:
                df = df.tail(max_rows)
                df.to_csv(path, index=False)
        else:
            df = pd.read_csv(path, header=None)
            if len(df) > max_rows:
                df = df.tail(max_rows)
                df.to_csv(path, header=False, index=False)
    except Exception as e:
        print(f"[!] Error trimming {path}: {e}")

def write_timestamp(timestamp):
    with open("detection/last_timestamp.txt", "w") as file_object:
                file_object.write(timestamp)

def grab_last_timestamp():
    with open('detection/last_timestamp.txt') as file_object:
        return file_object.read().strip()
    
def mark_ip_as_seen(ip: str, timestamp: str, score: int, verdict: str):
    with open("detection/seen_ips.csv", "a") as f:
        f.write(f"{ip},{timestamp},{score},{verdict}\n")

def load_seen_ips(file_path: str = "detection/seen_ips.csv") -> set[str]:
    if not os.path.exists(file_path):
        return set()
    with open(file_path, "r") as f:
        return set(row.strip().split(",")[0] for row in f if row.strip())
    
def calculate_verdict(country: str, isWhiteListed: bool, abuse_score: int):
    risk = 0

    if abuse_score >= 85:
        return "Malicious"
    elif abuse_score >= 60:
        risk += 60
    elif abuse_score >= 30:
        risk += 40
    elif abuse_score >= 10:
        risk += 20

    if country in HIGH_RISK_COUNTRIES:
        risk += 15

    if not isWhiteListed:
        risk += 10

    if abuse_score == 0 and isWhiteListed:
        return "Safe"

    # Final verdict thresholds
    if risk < 25:
        return "Safe"
    elif 25 <= risk < 65:
        return "Suspicious"
    else:
        return "Malicious"



def run_query(ip):
    querystring = {
        'ipAddress': ip, 
        'maxAgeInDays': 90
    }

    response = requests.request(method = 'GET', url = url, headers = headers, params = querystring)
    decodedResponse = json.loads(response.text)
    data = decodedResponse["data"]

    timestamp = datetime.utcnow().isoformat()
    country = data.get("countryCode", "N/A")
    isp = data.get("isp", "N/A")
    domain = data.get("domain", "N/A")
    abuse_score = data.get("abuseConfidenceScore", 0)
    is_whitelisted = data.get("isWhiteListed", False)
    
    verdict = calculate_verdict(country, is_whitelisted, abuse_score)
    print(f"[{timestamp}] {ip} -> {domain} -> {isp} scored {abuse_score} from {country} → {verdict}")
    mark_ip_as_seen(ip, timestamp, abuse_score, verdict)
    #trim_csv("detection/seen_ips.csv", 100)

def detect():
    seen_ips = load_seen_ips()
    last_ip_checked = grab_last_timestamp()
    with open('data/traffic_log.csv') as file_object:
        reader_object = csv.reader(file_object)
        
        for row in reader_object:
            if(len(row) < 3):
                continue
            #find the last ip checked
            if(row[0] < last_ip_checked):
                continue
            
            curr_ip = row[2].strip()
            if curr_ip in seen_ips:
                continue
            
            write_timestamp(row[0])
            run_query(curr_ip)
            seen_ips.add(curr_ip)


                
def start_detecting():
    while True:
        detect()
        time.sleep(0.5)

    



