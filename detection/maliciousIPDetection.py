import requests
import os
import json
import csv
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv('API_KEY')
url = 'https://api.abuseipdb.com/api/v2/check'

current_ip_set = set()

headers = {
    'Accept': 'application/json',
    'Key': API_KEY
}

def run_query(ip):
    querystring = {
        'ipAddress': ip, 
        'maxAgeInDays': 90
    }

    response = requests.request(method = 'GET', url = url, headers = headers, params = querystring)
    decodedResponse = json.loads(response.text)
    print(decodedResponse)

with open('data/traffic_log.csv') as file_object:
    reader_object = csv.reader(file_object);
    
    for row in reader_object:
        set_init_size = len(current_ip_set)
        curr_ip = row[2];
        current_ip_set.add(row[2])

        if(len(current_ip_set) > set_init_size):
            run_query(curr_ip)

