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
FAILED_PATTERN= re.compile(r'Failed password for .* from (\d{1,3}(?:\.\d{1,3}){3})')
LOGIN_PATTERN = re.compile(r'(Failed|Accepted) password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})')



def main():
    parser = argparse.ArgumentParser(description="threat intelligence IP checker")
    parser.add_argument("--bulk",help="path to a text file")
    parser.add_argument("--log", help=" path to a ssh log file")

    args=parser.parse_args()

    if args.log:
        counts=count_failed_logins(args.log)
        for ip,n in sorted(counts.items(),key=lambda x:x[1], reverse=True):
            print(f"{ip}: {n} failed logins")
        return
        
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
    try:
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

def check_ip(ip):
    print(f"\n --- checking {ip} ---")
    vt= check_virustotal(ip)
    ad=check_abuseipdb(ip)
    print(f"VirusTotal: {vt['malicious']} malicious" if vt else "VirusTotal: error")
    print(f"AbuseIPdb: {ad['reports']} reports, score {ad['score']}%" if ad else "AbuseIPdb: error")
    return vt,ad

def count_failed_logins(filename):
    counts={}
    try:
        with open(filename,"r") as f:
            for line in f:
                match = FAILED_PATTERN.search(line)
                if match:
                    ip=match.group(1)
                    if is_valid_ip(ip):
                        counts[ip]=counts.get(ip,0)+1
    except FileNotFoundError:
        print(f"FILE NOT FOUND: {filename}")
    return counts

def analyse_logs(filename):
    results={}

    try:
        with open(filename,"r") as f:
            for line in f:
                match = LOGIN_PATTERN.search(line)
                if not match:
                    continue

                status,user,ip=match.groups()

                if not is_valid_ip(ip):
                    continue

                if ip not in results:
                    results[ip]={"failures":0,"success": False,"users_tried": set()}

                if status == "Failed":
                    # add 1 to this ip's failure
                    results[ip]["failures"]+=1
                    # add user to this ip's users_tried
                    results[ip]["users_tried"].add(user)
                    
                else:
                    # if this IP's failures > 0, set success to true
                    if results[ip]["failures"] > 0:
                        results[ip]["success"]=True
                    
    except FileNotFoundError:
        print(f"FILE NOT FOUND: {filename}")

    return results

def score_ip(results,vt,ad):
    score=0
    reasons=[]
    if ad:
        if ad["score"]>75:
            score+=40
            reasons.append(f"AbuseIPdb score {ad['score']}")

        elif ad["score"]>25:
            score+=20
            reasons.append(f"AbuseIPdb score {ad['score']}")

    if vt and vt["malicious"] >= 5:
            score+=30
            reasons.append(f"VirusTotal: {vt['malicious']} engines flagged")

    if results["failures"] >= 5:
        score+=20
        reasons.append(f"{results['failures']} failed logins")
        if results["success"]:
            score+=20
            reasons.append("Login succeeded after failures")
            
    score=min(score,100)

    verdict = ""
    if score >= 70:
        verdict="MALICIOUS"
    elif score>=30:
        verdict="SUSPICIOUS"
    else:
        verdict="CLEAN"
    
    return {"verdict": verdict, "score": score, "reasons": reasons}


if __name__== "__main__":
    main()
