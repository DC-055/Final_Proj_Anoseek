#!/usr/bin/env python3
## DEDICATED CODE TO RUN ON HARDWARE ONLY!
import subprocess
import zmq
import json
import os
import requests
import signal
import sys
import zlib
from urllib.parse import urlparse
import threading

# destination to anomaly detection port -->
# REQ: 10.0.0.21 TO BACKEND'S LOCAL IP ADDRESS 
BACKEND_URL = os.environ.get("ANOSEEK_BACKEND_URL", "http://10.0.0.21:8001/predict")
BACKEND_TARGET = urlparse(BACKEND_URL)
BACKEND_HOST = BACKEND_TARGET.hostname
BACKEND_PORT = BACKEND_TARGET.port or 80
RATE_LIMIT_INTERVAL = 5.0  # seconds between allowed flows per IP

NPROBE_FIELDS = [
        "%IPV4_SRC_ADDR", "%IPV4_DST_ADDR", "%L4_SRC_PORT", "%L4_DST_PORT",
        "%PROTOCOL", "%L7_PROTO", "%IN_BYTES", "%OUT_BYTES",
        "%SERVER_TCP_FLAGS", "%FLOW_DURATION_MILLISECONDS",
        "%DURATION_IN", "%DURATION_OUT", "%MIN_TTL", "%LONGEST_FLOW_PKT",
        "%SHORTEST_FLOW_PKT", "%MIN_IP_PKT_LEN", "%MAX_IP_PKT_LEN",
        "%SRC_TO_DST_SECOND_BYTES", "%DST_TO_SRC_SECOND_BYTES",
        "%RETRANSMITTED_IN_BYTES", "%RETRANSMITTED_OUT_BYTES",
        "%SRC_TO_DST_AVG_THROUGHPUT", "%DST_TO_SRC_AVG_THROUGHPUT",
        "%NUM_PKTS_UP_TO_128_BYTES", "%NUM_PKTS_128_TO_256_BYTES",
        "%NUM_PKTS_256_TO_512_BYTES", "%NUM_PKTS_512_TO_1024_BYTES",
        "%NUM_PKTS_1024_TO_1514_BYTES", "%TCP_WIN_MAX_IN", "%TCP_WIN_MAX_OUT",
        "%ICMP_IPV4_TYPE", "%DNS_QUERY_ID", "%DNS_QUERY_TYPE",
        "%DNS_TTL_ANSWER", "%FTP_COMMAND_RET_CODE",
]

# acitvating flow exporter for active listening
NPROBE_CMD = [ "sudo", "nprobe", "-i", "wlan0",
        "--zmq", "tcp://*:5556", "--zmq-format", "j",
        "--json-labels", "-t", "10", "-l", "30",
        "-T", " ".join(NPROBE_FIELDS)
        ]

print("(1) starting nProbe listening...")

nprobe_process = subprocess.Popen(NPROBE_CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

time.sleep(2)

# check for nProbe load errors
if nprobe_process.poll() is not None:
    stderr = nprobe_process.stderr.read().decode("utf-8", errors="replace")
    print("[NPROBE ERROR] nProbe exited during startup")
    if stderr.strip():
        print(stderr.strip())
    sys.exit(1)

print("(2) Connecting to ZMQ Stream...")

context = zmq.Context()

# activating zmq as a listener (One-way communication)
subscriber = context.socket(zmq.SUB)
subscriber.connect("tcp://127.0.0.1:5556")
# listen to all types of messages
subscriber.setsockopt_string(zmq.SUBSCRIBE, "")

def cleanup(sig=None, frame=None):
    print("(3) Shutting down...\n")
    nprobe_process.terminate()
    subscriber.close()
    context.term()
    sys.exit(0)


# activating cleanup upon CTRL+C press to terminate
signal.signal(signal.SIGINT, cleanup)

print("(4) Listening for flows \n")

# blocked_ips: set[str] = set()
# rate_limited_ips: dict[str, float] = {}  # ip -> last_sent timestamp

def sync_enforcement():
    global blocked_ips, rate_limited_ips
    while True:
        try:
            r = requests.get(f"http://{BACKEND_HOST}:{BACKEND_PORT}/agent/enforcement", timeout=3)
            data = r.json()
            blocked_ips = set(data["blocked_ips"])
            rate_limited_ips = {ip: rate_limited_ips.get(ip, 0) for ip in data["rate_limited_ips"]}
        except Exception as e:
            print("[SYNC ERROR]", e)
        time.sleep(30)  # sync every 30 seconds

threading.Thread(target=sync_enforcement, daemon=True).start()


# removing flows that go in between backend-host to pi hardware
def should_skip_flow(flow):
    src_ip = flow.get("IPV4_SRC_ADDR")
    dst_ip = flow.get("IPV4_DST_ADDR")
    src_port = int(flow.get("L4_SRC_PORT") or 0)
    dst_port = int(flow.get("L4_DST_PORT") or 0)
    endpoints = {src_ip, dst_ip}
    ports = {src_port, dst_port}

    if BACKEND_HOST in endpoints and BACKEND_PORT in ports:
       return True
    if BACKEND_HOST in endpoints and 22 in ports:
       return True # skipping SSH
    if src_ip == "0.0.0.0" and 22 in ports:
       return True # skipping SSH with unknown placeholders
    if BACKEND_HOST in endpoints and 5353 in ports:
       return True # skipping mDNS
    if src_ip in blocked_ips:
        return True
    if src_ip in rate_limited_ips:
        if time.time() - rate_limited_ips[src_ip] < RATE_LIMIT_INTERVAL:
            return True
        # interval elapsed — allow through and update timestamp
        rate_limited_ips[src_ip] = time.time()

    return False

# json formatting for backend to retrieve flows
def send_flow(flow):
    src_ip = flow.get("IPV4_SRC_ADDR")
    try:
        response = requests.post(BACKEND_URL, json=flow, timeout=3)
        response.raise_for_status()
        result = response.json()
        print("[MODEL]", result)

        action = result[0].get("action") if isinstance(result, list) else result.get("action")
        if action == "block" and src_ip:
            blocked_ips.add(src_ip)
        elif action == "rate_limit" and src_ip:
            rate_limited_ips[src_ip] = time.time()
    except requests.exceptions.RequestException as e:
        print("[BACKEND ERROR]", e)
    except ValueError:
        print("[BACKEND ERROR] Non-JSON response:", response.text)


while True:
    try:
        # flow extractions are received in two-parts
        frames = subscriber.recv_multipart()
        if len(frames) < 2:
           continue
        topic = frames[0]
        compressed_payload = frames[1]

        # payload is decompressed with zlib --> skipping 'hello'/'event' messages
        if not compressed_payload.startswith(b'x\x9c'):
           print("[SKIP]")
           continue
        decompressed_bytes = zlib.decompress(compressed_payload)
        json_str = decompressed_bytes.decode('utf-8')

        # skipping empty messages
        if not json_str:
           print("[INFO] Received empty message")
        else:
            recv = json.loads(json_str)
            # skipping control / template messages
            if isinstance(recv, dict):
                if "probe" in recv or "PEN" in recv:
                    print("[SKIPPED] nProbe control & PEN dict Template")
                    continue
                if "PROTOCOL" in recv:
                    if should_skip_flow(recv): # skipping pi<-->backend traffic [dict]
                        print("[SKIPPED] backend traffic")
                        continue
                    flow_json = json.dumps(recv)
                    print("[FLOW DATA]", flow_json)
                    send_flow(recv)
            elif isinstance(recv, list):
                # extracting numerous flows
                for flow in recv:
                    if "PROTOCOL" in flow:
                        if should_skip_flow(flow): # skipping pi<-->backend traffic [kist]
                            print("[SKIPPED] backend traffic")
                            continue
                        flow_json = json.dumps(flow)
                        print("[FLOW DATA]", flow_json)
                        send_flow(flow)
                    else:
                        print("[SKIPPED] PEN template message")

    except Exception as e:
        print("[ERROR]", e)
