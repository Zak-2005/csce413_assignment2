# Port Knocking Implementation

## Overview

This is a custom port knocking system that protects the SSH service on port 2222. The protected port is blocked by default using iptables. Only after a client sends TCP connections to ports 1234, 5678, and 9012 in the correct order (within a 15-second window) does the firewall open port 2222 for that specific IP address.

## Architecture

```
knock_server.py   — Server-side: listens for knocks, manages iptables rules
knock_client.py   — Client-side: sends the knock sequence
demo.sh           — Demo script showing the full flow
Dockerfile        — Container with iptables and Python
```

## How It Works

### Knock Sequence
1. Client sends TCP connection to port **1234**
2. Client sends TCP connection to port **5678**
3. Client sends TCP connection to port **9012**
4. Server validates the sequence and opens port **2222** for the client's IP

### Server Design
- **KnockTracker** — Thread-safe class tracking per-IP progress through the sequence
- **Firewall Manager** — Uses `iptables` to dynamically add/remove rules
- **Port Listeners** — One TCP listener thread per knock port
- **Timing Window** — Sequence must complete within 15 seconds
- **Auto-expiry** — Port access expires after 30 seconds

### Firewall Rules
```bash
# Default: block protected port
iptables -A INPUT -p tcp --dport 2222 -j DROP

# After successful knock: allow specific IP
iptables -I INPUT 1 -s <source_ip> -p tcp --dport 2222 -j ACCEPT

# After timeout: remove the allow rule
iptables -D INPUT -s <source_ip> -p tcp --dport 2222 -j ACCEPT
```

## Usage

### Start the server
```bash
# With Docker Compose
docker compose up port_knocking

# Standalone
python3 knock_server.py --sequence 1234,5678,9012 --protected-port 2222
```

### Send knock sequence
```bash
python3 knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012 --check
```

### Run the demo
```bash
bash demo.sh 172.20.0.40
```

## Security Analysis

**Strengths:**
- Adds pre-authentication layer before service is reachable
- Per-IP tracking prevents interference between users
- Timing constraints limit brute-force feasibility

**Limitations:**
- Knock sequence transmitted in plaintext (observable by network attacker)
- TCP knocks visible in firewall logs
- Determined attacker could brute-force a 3-port sequence

**Improvements:**
- Use Single Packet Authorization (SPA) for cryptographic verification
- Increase sequence length for larger search space
- Combine with VPN or IP whitelisting
