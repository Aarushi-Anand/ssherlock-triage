import requests
from dotenv import load_dotenv
import os
load_dotenv()

VT_API_KEY=os.getenv("VT_API_KEY")
ABUSEIPDB_KEY=os.getenv("ABUSEIPDB_KEY")

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

ips=input("enter IPs separated by comma: ").split(",")
for ip in ips:
    check_ip(ip.strip())