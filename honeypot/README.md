# SSH Honeypot

## Overview

This is an SSH honeypot that simulates a realistic SSH server to attract and log unauthorized access attempts. It's designed to detect attackers performing network reconnaissance and credential brute-forcing.

## Architecture

```
honeypot.py       — Main server: TCP listener, SSH simulation, fake shell
logger.py         — Structured JSON logging with alerting
logs/             — Log output directory
  connections.jsonl   — Connection/disconnection events
  auth_attempts.jsonl — Username/password attempts
  commands.jsonl      — Shell commands executed
  alerts.jsonl        — Security alerts
  honeypot.log        — Human-readable combined log
analysis.md       — Analysis of observed attacks
```

## Features

- **Realistic SSH banner** (`SSH-2.0-OpenSSH_8.9p1 Ubuntu`) that matches a real server
- **Fake authentication** — accepts on 3rd attempt to maximize intelligence gathering
- **Interactive fake shell** with commands: `ls`, `cd`, `cat`, `pwd`, `whoami`, `id`, `uname`, `ps`, `echo`, `history`
- **Fake filesystem** — realistic directory structure with decoy files
- **Structured JSON logging** — every event recorded for analysis
- **Automatic alerting** — detects brute force attacks, suspicious usernames, and dangerous commands

## How to Run

### With Docker Compose (from repo root)
```bash
docker compose up honeypot
```

### Standalone
```bash
cd honeypot
python3 honeypot.py
```

## Testing

```bash
# Connect to the honeypot
ssh admin@localhost -p 2222

# Try various credentials — all are logged
# After "successful" login, try commands like:
ls
cat /etc/passwd
whoami
wget http://example.com
```

## Log Analysis

```bash
# View authentication attempts
cat logs/auth_attempts.jsonl | python3 -m json.tool

# View security alerts
cat logs/alerts.jsonl

# View all commands executed
cat logs/commands.jsonl
```
