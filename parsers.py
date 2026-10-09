import re
import ipaddress

IP_PATTERN= re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
LOGIN_PATTERN = re.compile(r'(Failed|Accepted) password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})')

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
                if ipaddress.ip_address(ip).is_private:
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
