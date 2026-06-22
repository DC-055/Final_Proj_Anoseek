"""Generate a 1000-row synthetic test CSV matching the NF-CSE-CIC-IDS2018 format.

Distribution: ~82 % benign background traffic from 12 normal hosts, plus three
concentrated attack series (SSH brute-force, DoS, SQL injection) from 3 dedicated
attacker IPs interspersed throughout the file.
"""
import random
import csv
import sys
import os

random.seed(42)

# Load the real feature medians from the trained bundle so Benign rows
# land in the correct region of feature space after scaling.
_MEDIANS: dict = {}
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
    import joblib
    _bundle = joblib.load(os.path.join(os.path.dirname(__file__),
                          "..", "backend", "artifacts", "bundle.joblib"))
    _MEDIANS = _bundle.get("medians", {})
    print(f"[info] Loaded {len(_MEDIANS)} feature medians from bundle")
except Exception as e:
    print(f"[warn] Could not load bundle medians ({e}); using synthetic values")

COLS = [
    "IPV4_SRC_ADDR", "L4_SRC_PORT", "IPV4_DST_ADDR", "L4_DST_PORT",
    "PROTOCOL", "L7_PROTO",
    "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS",
    "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS", "DURATION_IN", "DURATION_OUT",
    "MIN_TTL", "MAX_TTL",
    "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT",
    "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN",
    "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
    "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES", "RETRANSMITTED_OUT_PKTS",
    "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES", "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT",
    "ICMP_TYPE", "ICMP_IPV4_TYPE",
    "DNS_QUERY_ID", "DNS_QUERY_TYPE", "DNS_TTL_ANSWER", "DNS_QUERY_LEN",
    "FTP_COMMAND_RET_CODE",
    "Label", "Attack",
]

# 12 normal hosts + 3 dedicated attacker IPs
SRC_IPS_BENIGN = (
    [f"192.168.1.{i}" for i in range(1, 10)] +   # 9 workstations
    [f"10.0.0.{i}"    for i in range(1, 4)]       # 3 servers
)  # 12 total

SRC_IPS_ATTACK = [
    "192.168.1.10",   # SSH brute-forcer
    "10.0.0.4",       # DoS attacker
    "10.0.0.5",       # SQL injection
]

SRC_IPS = SRC_IPS_BENIGN + SRC_IPS_ATTACK

DST_IPS = [f"172.16.0.{i}" for i in range(1, 6)] + \
          ["8.8.8.8", "1.1.1.1", "93.184.216.34"]

IP_ATTACK_PROFILE = {
    **{ip: "Benign" for ip in SRC_IPS_BENIGN},
    "192.168.1.10": "SSH-Bruteforce",
    "10.0.0.4":     "DoS attacks-Hulk",
    "10.0.0.5":     "SQL Injection",
}

# Row budget: 820 benign (~82 %) + 180 attack (~18 %) = 1000
_BENIGN_TOTAL = 820
_ATTACK_TOTAL = 180


def row_for(src_ip, attack_label):
    r = random.random
    ri = random.randint

    proto = 6 if attack_label not in ("Benign",) or r() > 0.2 else 17
    is_tcp = proto == 6

    if attack_label == "Benign":
        # Use real training medians so values land in the correct feature region.
        def _m(col, fallback):
            v = _MEDIANS.get(col, fallback)
            noise = random.uniform(0.8, 1.2)
            return max(0, int(v * noise))
        in_bytes  = _m("IN_BYTES",  1200)
        out_bytes = _m("OUT_BYTES", 800)
        in_pkts   = _m("IN_PKTS",   8)
        out_pkts  = _m("OUT_PKTS",  6)
        duration  = _m("FLOW_DURATION_MILLISECONDS", 3000)
        l7        = random.choice([7, 91, 443, 0])
        dst_port  = random.choice([80, 443, 53, 22, 8080])
    elif attack_label in ("SSH-Bruteforce", "FTP-BruteForce", "Brute Force -Web", "Brute Force -XSS"):
        in_bytes  = ri(40, 500)
        out_bytes = ri(40, 500)
        in_pkts   = ri(1, 5)
        out_pkts  = ri(1, 5)
        duration  = ri(10, 2000)
        l7        = 22 if "SSH" in attack_label else 21 if "FTP" in attack_label else 7
        dst_port  = 22 if "SSH" in attack_label else 21 if "FTP" in attack_label else 80
    elif "DoS" in attack_label or "DDoS" in attack_label or "DDOS" in attack_label:
        in_bytes  = ri(50000, 5000000)
        out_bytes = ri(1000, 100000)
        in_pkts   = ri(500, 50000)
        out_pkts  = ri(10, 1000)
        duration  = ri(1, 5000)
        l7        = 7
        dst_port  = 80
    elif attack_label in ("SQL Injection",):
        in_bytes  = ri(300, 8000)
        out_bytes = ri(300, 8000)
        in_pkts   = ri(2, 20)
        out_pkts  = ri(2, 20)
        duration  = ri(50, 10000)
        l7        = 7
        dst_port  = 80
    else:  # Infilteration, Bot, etc.
        in_bytes  = ri(100, 5000)
        out_bytes = ri(100, 5000)
        in_pkts   = ri(1, 30)
        out_pkts  = ri(1, 30)
        duration  = ri(100, 30000)
        l7        = random.choice([7, 0, 443])
        dst_port  = random.choice([80, 443, 6667, 4444])

    src_port     = ri(1024, 65535)
    min_ttl      = random.choice([32, 64, 128, 255])
    max_ttl      = min_ttl + ri(0, 5)
    longest_pkt  = ri(64, 1514)
    shortest_pkt = ri(40, longest_pkt)
    min_ip_pkt   = shortest_pkt
    max_ip_pkt   = longest_pkt

    dur_s          = max(duration / 1000.0, 0.001)
    s2d_throughput = int(in_bytes  / dur_s)
    d2s_throughput = int(out_bytes / dur_s)

    ret_in_b  = 0 if r() > 0.1 else ri(0, in_bytes  // 4)
    ret_in_p  = 0 if r() > 0.1 else ri(0, in_pkts   // 4)
    ret_out_b = 0 if r() > 0.1 else ri(0, out_bytes // 4)
    ret_out_p = 0 if r() > 0.1 else ri(0, out_pkts  // 4)

    total_pkts = in_pkts + out_pkts
    p_128  = ri(0, total_pkts)
    p_256  = ri(0, max(0, total_pkts - p_128))
    p_512  = ri(0, max(0, total_pkts - p_128 - p_256))
    p_1024 = ri(0, max(0, total_pkts - p_128 - p_256 - p_512))
    p_1514 = max(0, total_pkts - p_128 - p_256 - p_512 - p_1024)

    tcp_flags        = ri(0, 255) if is_tcp else 0
    client_tcp_flags = ri(0, 63)  if is_tcp else 0
    server_tcp_flags = ri(0, 63)  if is_tcp else 0
    tcp_win_in       = ri(1024, 65535) if is_tcp else 0
    tcp_win_out      = ri(1024, 65535) if is_tcp else 0

    icmp_type      = ri(0, 18) if proto == 1 else 0
    dns_query_id   = ri(0, 65535) if dst_port == 53 else 0
    dns_query_type = 1             if dst_port == 53 else 0
    dns_ttl        = ri(30, 3600)  if dst_port == 53 else 0
    dns_query_len  = ri(10, 60)    if dst_port == 53 else 0

    dst_ip = random.choice(DST_IPS)

    return {
        "IPV4_SRC_ADDR":              src_ip,
        "L4_SRC_PORT":                src_port,
        "IPV4_DST_ADDR":              dst_ip,
        "L4_DST_PORT":                dst_port,
        "PROTOCOL":                   proto,
        "L7_PROTO":                   l7,
        "IN_BYTES":                   in_bytes,
        "IN_PKTS":                    in_pkts,
        "OUT_BYTES":                  out_bytes,
        "OUT_PKTS":                   out_pkts,
        "TCP_FLAGS":                  tcp_flags,
        "CLIENT_TCP_FLAGS":           client_tcp_flags,
        "SERVER_TCP_FLAGS":           server_tcp_flags,
        "FLOW_DURATION_MILLISECONDS": duration,
        "DURATION_IN":                duration // 2,
        "DURATION_OUT":               duration // 2,
        "MIN_TTL":                    min_ttl,
        "MAX_TTL":                    max_ttl,
        "LONGEST_FLOW_PKT":           longest_pkt,
        "SHORTEST_FLOW_PKT":          shortest_pkt,
        "MIN_IP_PKT_LEN":             min_ip_pkt,
        "MAX_IP_PKT_LEN":             max_ip_pkt,
        "SRC_TO_DST_SECOND_BYTES":    s2d_throughput,
        "DST_TO_SRC_SECOND_BYTES":    d2s_throughput,
        "RETRANSMITTED_IN_BYTES":     ret_in_b,
        "RETRANSMITTED_IN_PKTS":      ret_in_p,
        "RETRANSMITTED_OUT_BYTES":    ret_out_b,
        "RETRANSMITTED_OUT_PKTS":     ret_out_p,
        "SRC_TO_DST_AVG_THROUGHPUT":  s2d_throughput,
        "DST_TO_SRC_AVG_THROUGHPUT":  d2s_throughput,
        "NUM_PKTS_UP_TO_128_BYTES":   p_128,
        "NUM_PKTS_128_TO_256_BYTES":  p_256,
        "NUM_PKTS_256_TO_512_BYTES":  p_512,
        "NUM_PKTS_512_TO_1024_BYTES": p_1024,
        "NUM_PKTS_1024_TO_1514_BYTES":p_1514,
        "TCP_WIN_MAX_IN":             tcp_win_in,
        "TCP_WIN_MAX_OUT":            tcp_win_out,
        "ICMP_TYPE":                  icmp_type,
        "ICMP_IPV4_TYPE":             icmp_type,
        "DNS_QUERY_ID":               dns_query_id,
        "DNS_QUERY_TYPE":             dns_query_type,
        "DNS_TTL_ANSWER":             dns_ttl,
        "DNS_QUERY_LEN":              dns_query_len,
        "FTP_COMMAND_RET_CODE":       0,
        "Label":                      attack_label,
        "Attack":                     attack_label,
    }


# ── Build per-IP flow pools ──────────────────────────────────────────────────

ip_pools: dict[str, list] = {}

# Benign IPs: divide 820 rows roughly evenly
benign_base = _BENIGN_TOTAL // len(SRC_IPS_BENIGN)
benign_extra = _BENIGN_TOTAL % len(SRC_IPS_BENIGN)
for i, ip in enumerate(SRC_IPS_BENIGN):
    n = benign_base + (1 if i < benign_extra else 0)
    ip_pools[ip] = [row_for(ip, "Benign") for _ in range(n)]

# Attack IPs: divide 180 rows roughly evenly
attack_base = _ATTACK_TOTAL // len(SRC_IPS_ATTACK)
attack_extra = _ATTACK_TOTAL % len(SRC_IPS_ATTACK)
for i, ip in enumerate(SRC_IPS_ATTACK):
    n = attack_base + (1 if i < attack_extra else 0)
    ip_pools[ip] = [row_for(ip, IP_ATTACK_PROFILE[ip]) for _ in range(n)]

# ── Interleave ───────────────────────────────────────────────────────────────
# Benign IPs: small random bursts (3-8) — normal background chatter
# Attack IPs: large bursts (15-25) — concentrated attack series

def _burst(ip: str, pool: list) -> int:
    if ip in SRC_IPS_ATTACK:
        return min(random.randint(15, 25), len(pool))
    return min(random.randint(3, 8), len(pool))

active = list(SRC_IPS)
random.shuffle(active)
rows: list[dict] = []

while active:
    ip = active.pop(0)
    pool = ip_pools[ip]
    burst = _burst(ip, pool)
    rows.extend(pool[:burst])
    del pool[:burst]
    if pool:
        insert_at = random.randint(1, max(1, len(active)))
        active.insert(insert_at, ip)

# ── Write CSV ────────────────────────────────────────────────────────────────

out_path = "datasets/test_1000.csv"
os.makedirs("datasets", exist_ok=True)

with open(out_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=COLS)
    writer.writeheader()
    writer.writerows(rows)

benign_count = sum(1 for r in rows if r["Label"] == "Benign")
attack_count = len(rows) - benign_count
print(f"Written {len(rows)} rows to {out_path}")
print(f"  Benign: {benign_count} ({benign_count/len(rows)*100:.1f} %)")
print(f"  Attack: {attack_count} ({attack_count/len(rows)*100:.1f} %)")
print()
ip_summary: dict[str, int] = {}
for r in rows:
    ip = r["IPV4_SRC_ADDR"]
    ip_summary[ip] = ip_summary.get(ip, 0) + 1
for ip, cnt in sorted(ip_summary.items()):
    print(f"  {ip}: {cnt} rows  ({IP_ATTACK_PROFILE[ip]})")
