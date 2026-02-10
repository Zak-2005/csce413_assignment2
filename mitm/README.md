# MITM Traffic Capture & Analysis

## Overview

This directory contains tools for performing a man-in-the-middle (MITM) attack on the unencrypted MySQL communication between the web application and the database.

## The Vulnerability

The web application communicates with MySQL over port 3306 with **SSL/TLS explicitly disabled**. All SQL queries, results, and sensitive data (including API tokens) are transmitted in plaintext.

## Tools

### capture.py
A Python script using Scapy to capture and analyze MySQL traffic on the Docker bridge interface.

**Usage:**
```bash
# Auto-detect interface and capture 100 packets
sudo python3 capture.py

# Specify interface and count
sudo python3 capture.py --interface br-<network_id> --count 200

# Save to pcap file
sudo python3 capture.py --interface br-<network_id> --output capture.pcap

# Analyze existing pcap
sudo python3 capture.py --pcap capture.pcap
```

### Alternative: tcpdump
```bash
# Find the Docker bridge interface
NETWORK_ID=$(docker network inspect 2_network_vulnerable_network --format '{{.Id}}' | cut -c1-12)

# Capture MySQL traffic
sudo tcpdump -i br-${NETWORK_ID} -A -s 0 'port 3306'
```

## Steps to Reproduce

1. Start the environment: `docker compose up --build`
2. Start packet capture (see above)
3. Generate traffic: open `http://localhost:5001/api/secrets` in a browser
4. Observe plaintext SQL queries and Flag 1 in the captured traffic
5. Use Flag 1 as an API token to access `http://172.20.0.21:8888/flag` for Flag 3

## Artifacts

After running the capture, results are saved to:
- `mitm_results.txt` — Summary of captured data, flags, and SQL queries
- `capture.pcap` — Raw packet capture (if `--output` specified)
