import requests
import os
import time
from cache import init_db, get_cached, save_cache
from dotenv import load_dotenv
load_dotenv()

VT_API_KEY=os.getenv("VT_API_KEY")
ABUSEIPDB_KEY=os.getenv("ABUSEIPDB_KEY")


def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers={"x-apikey" : VT_API_KEY}
    try:
        time.sleep(15)
        r=requests.get(url,headers=headers, timeout=10)

    except requests.RequestException:
        return None

    if r.status_code==200:
        stats=r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"malicious":stats["malicious"]}
    return None

def check_abuseipdb(ip):
    url="https://api.abuseipdb.com/api/v2/check"
    headers={"Key": ABUSEIPDB_KEY,"Accept": "application/json"}
    params={"ipAddress": ip,"maxAgeInDays":90}
    try:
        r=requests.get(url,headers=headers,params=params, timeout=10)

    except requests.RequestException:
        return None

    if r.status_code==200:
        data=r.json()
        score=data["data"]["abuseConfidenceScore"]
        reports=data["data"]["totalReports"]
        return {"score": score, "reports": reports}
    return None

def check_ip(ip,conn):
    cached=get_cached(conn, ip)
    if cached:
        return cached["vt"],cached["ad"]
    vt= check_virustotal(ip)
    ad=check_abuseipdb(ip)

    if vt or ad:
        save_cache(conn,ip,{"vt":vt,"ad":ad})
    return vt,ad