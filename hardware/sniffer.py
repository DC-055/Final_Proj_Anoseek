#!/usr/bin/env python3
## DEDICATED CODE TO RUN ON HARDWARE ONLY!
import subprocess
import zmq
import json
import requests
import signal
import sys
import time
import zlib

# destination to anomaly detection port -->
#BACKEND_URL = "http://127.0.0.1:8001/predict"

# acitvating flow exporter for active listening
NPROBE_CMD = [ "sudo", "nprobe", "-i", "wlan0",
        "--zmq", "tcp://*:5556", "--zmq-format", "j",
        "--json-labels", "-t", "10", "-l", "30",
        "-T", "%PROTOCOL %L7_PROTO %IN_BYTES %OUT_BYTES "
        "%SERVER_TCP_FLAGS %FLOW_DURATION_MILLISECONDS "
        "%DURATION_IN %DURATION_OUT %MIN_TTL %LONGEST_FLOW_PKT %SHORTEST_FLOW_PKT"
        "%MIN_IP_PKT_LEN %MAX_IP_PKT_LEN %SRC_TO_DST_SECOND_BYTES %DST_TO_SRC_SECOND_BYTES"
        "%RETRANSMITTED_IN_BYTES %RETRANSMITTED_OUT_BYTES %TCP_WIN_MAX_IN %TCP_WIN_MAX_OUT"
        "%SRC_TO_DST_AVG_THROUGHPUT %DST_TO_SRC_AVERAGE_THROUGHPUT %NUM_PACKETS_UP_TO_128_BYTES"
        "%NUM_PKTS_128_TO_256_BYTES %NUM_PKTS_256_TO_512_BYTES %NUM_PKTS_512_TO_1024_BYTES"
        "%NUM_PKTS_1024_TO_1514_BYTES %TCP_WIN_MAX_IN %TCP_WIN_MAX_OUT"
        "%ICMP_IPV4_TYPE %DNS_QUERY_ID %DNS_QUERY_TYPE"
        ]

print("(1) starting nProbe listening...")

nprobe_process = subprocess.Popen(NPROBE_CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

time.sleep(2)

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
            elif isinstance(recv, list):
                # extracting numerous flows
                for flow in recv:
                    if "PROTOCOL" in flow:
                        flow_json = json.dumps(flow)
                        print("[FLOW DATA]", flow_json)
                    else:
                        print("[SKIPPED] PEN template message")
                # response = requests.post(BACKEND_URL, json=flow, timeout=3)
                # print("[MODEL]", response.json())

    except Exception as e:
        print("[ERROR]", e)