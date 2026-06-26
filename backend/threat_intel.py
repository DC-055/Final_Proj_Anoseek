from pathlib import Path
import  requests

ARTIFACTS = Path("artifacts")

def ipsun_l3_import():
    url="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
    response = requests.get(url)
    file_path = ARTIFACTS / "IPsum_L3.txt"
    if response.status_code == 200:
        raw_lines = response.text.splitlines()
        clean_ips = [line.strip() for line in raw_lines if line and not line.startswith('#')]
        
        with open(file_path, "w", encoding="utf-8") as file:
            for ip in clean_ips:
                file.write(f"{ip}\n")
        return True
    
    else:
        return False