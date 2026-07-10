import requests
import argparse
import re
import ipaddress
from dotenv import load_dotenv
import os
load_dotenv()

VT_API_KEY=os.getenv("VT_API_KEY")
ABUSEIPDB_KEY=os.getenv("ABUSEIPDB_KEY")
IP_PATTERN= re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def main():
    parser = argparse.ArgumentParser(description="threat intelligence IP checker")
    parser.add_argument("--bulk",help="path to a text file")
    args=parser.parse_args()

    if args.bulk:
        ips = read_ips(args.bulk)
    else:
        raw_ips = input("Enter IPs separated by commas: ")
        ips = [ip.strip() for ip in raw_ips.split(",") if ip.strip()]
    
    if not ips:
        print("No IPs found, exiting.")
        return
    print(f"Loaded {len(ips)} ips: ")

    for ip in ips:
        print(ip)
        check_ip(ip)

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def read_ips(filepath):
    ips=[]
    try: 
        with open(filepath,"r") as f:
            for line_num, line in enumerate(f, start=1): #python unpacking to store line number and text on the line which we get using enumerate
                candidates = IP_PATTERN.findall(line)
                for ip in candidates:
                    if is_valid_ip(ip):
                        ips.append(ip)
                    else:
                        print(f" Skipping IP {ip} on line {line_num}")
    
    except FileNotFoundError:
        print(f"File not found: {filepath}")
    except PermissionError:
        print(f"Permission denied reading: {filepath}")
    except Exception as e:
        print(f"Unexpected Error reading file {filepath}: {e}")

    return ips


def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers={"x-apikey" : VT_API_KEY}
    r=requests.get(url,headers=headers)
    if r.status_code==200:
        data=r.json()
        stats=data["data"]["attributes"]["last_analysis_stats"]
        malicious=stats["malicious"]
        return f"VirusTotal: {malicious} engines flagged as malicious"
    return "VirusTotal: error fetching data"

def check_abuseipdb(ip):
    url="https://api.abuseipdb.com/api/v2/check"
    headers={"Key": ABUSEIPDB_KEY,"Accept": "application/json"}
    params={"ipAddress": ip,"maxAgeInDays":90}

    r=requests.get(url,headers=headers,params=params)

    if r.status_code==200:
        data=r.json()
        score=data["data"]["abuseConfidenceScore"]
        reports=data["data"]["totalReports"]
        return f"AbuseIPDB: {reports} reports, confidence score {score}%"
    return "AbuseIPDB: error fetching data"

def check_ip(ip):
    print(f"\n --- checking {ip} ---")
    print(check_virustotal(ip))
    print(check_abuseipdb(ip))


if __name__== "__main__":
    main()
