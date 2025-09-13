from scapy.all import sniff, Raw, TCP, IP
import re, csv
from datetime import datetime
from collections import defaultdict

OUTCSV = "captured_traffic.csv"

# Track login attempts and packet counts per IP
login_attempts = defaultdict(int)
packet_counts = defaultdict(int)

# Initialize CSV with headers
with open(OUTCSV, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Timestamp","SrcIP","DstIP","DstPort","Encryption","Username","Password","Suspicious"])

def classify_encryption(dport, payload_bytes):
    # Basic classification by port
    if dport in [443,22,465,993,995,8443]:
        return "Encrypted ✅"
    elif dport in [80,8080,21,23,25,8000]:
        return "Plaintext ❌"
    else:
        return f"Unclassified (Port {dport})"

def cb(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    dport = pkt[TCP].dport
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    username = password = ""
    suspicious = ""

    # Encryption status
    if pkt.haslayer(Raw):
        enc_status = classify_encryption(dport, bytes(pkt[Raw].load))
    else:
        enc_status = classify_encryption(dport, b"")

    # Credential extraction
    if pkt.haslayer(Raw):
        try:
            s = pkt[Raw].load.decode(errors="ignore")
            if "POST" in s and ("username=" in s or "password=" in s):
                u = re.search(r"username=([^& \r\n]+)", s)
                p = re.search(r"password=([^& \r\n]+)", s)
                if u and p:
                    username, password = u.group(1), p.group(1)
                    login_attempts[src] += 1
                    print(f"[!] Credential Captured: {username}:{password}")
        except:
            pass

    # Count packets per source
    packet_counts[src] += 1

    # Suspicious flags (combine multiple alerts)
    flags = []
    if login_attempts[src] > 3:
        flags.append("Possible Brute Force 🚨")
    if packet_counts[src] > 100:
        flags.append("High Traffic (DoS?) ⚠️")

    suspicious = "; ".join(flags)

    # Save to CSV
    with open(OUTCSV,"a",newline="") as f:
        w = csv.writer(f)
        w.writerow([ts,src,dst,dport,enc_status,username,password,suspicious])

print("[*] Starting sniffer with suspicious pattern detection...")
sniff(prn=cb, timeout=60, iface=["lo","eth0"])
