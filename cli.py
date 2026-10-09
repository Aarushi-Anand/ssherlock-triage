import argparse
from parsers import read_ips, analyse_logs
from intel import check_ip
from scoring import score_ip
from cache import init_db

def main():
    parser = argparse.ArgumentParser(description="threat intelligence IP checker")
    parser.add_argument("--bulk",help="path to a text file")
    parser.add_argument("--log", help="path to a ssh log file")

    args=parser.parse_args()

    if args.log:
        data=analyse_logs(args.log)
        top = sorted(data.items(), key=lambda x:x[1]["failures"], reverse=True)[:5]
        conn=init_db()
        for ip, info in top:
            vt,ad =check_ip(ip,conn)
            result=score_ip(info,vt,ad)
            print (f"\n{ip} -> {result['verdict']} (score {result['score']})")
            for r in result["reasons"]:
                print(f"    - {r}")
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


if __name__== "__main__":
    main()