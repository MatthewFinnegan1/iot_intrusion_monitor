import requests
import os
import json
import csv
import time
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv('API_KEY')
url = 'https://api.abuseipdb.com/api/v2/check'

seen_ips = set()

headers = {
    'Accept': 'application/json',
    'Key': API_KEY
}

def wipe_csv(file_path):
    with open(file_path, "w") as file_object:
        file_object.truncate(0)

def grab_last_timestamp():
    with open('detection/last_timestamp.txt') as file_object:
        return file_object.read().strip()

def run_query(ip):
    querystring = {
        'ipAddress': ip, 
        'maxAgeInDays': 90
    }

    response = requests.request(method = 'GET', url = url, headers = headers, params = querystring)
    decodedResponse = json.loads(response.text)
    print(decodedResponse)

def detect():
    last_ip_checked = grab_last_timestamp()
    with open('data/traffic_log.csv') as file_object:
        reader_object = csv.reader(file_object)
        
        for row in reader_object:
            
            #find the last ip checked
            if(row[0] < last_ip_checked):
                continue
            
            init_size = len(seen_ips)
            curr_ip = row[2];
            seen_ips.add(row[2])
            wipe_csv('detection/last_timestamp.txt')

            #query ip only if it hasn't been seen
            if(len(seen_ips) > init_size):
                run_query(curr_ip)
def start_detecting():
    while True:
        detect()
        time.sleep(10)

    



