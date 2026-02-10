"""
Honeypot Logger
Assignment 2: Network Security

Structured logging for the SSH honeypot. Writes JSON-formatted events
to log files and stdout for real-time monitoring.

Log Types:
- connection: New TCP connection from attacker
- disconnect: Attacker disconnected (with session duration)
- auth_attempt: Authentication attempt with username/password
- command: Shell command executed by attacker
- alert: Suspicious activity detected
- event: General events (server start, errors, etc.)
"""

import json
import logging
import os
import threading
import time
from collections import defaultdict
from datetime import datetime


class HoneypotLogger:
    """Structured logger for the honeypot with alerting."""

    # Thresholds for alerts
    BRUTE_FORCE_THRESHOLD = 5  # auth attempts before alerting
    BRUTE_FORCE_WINDOW = 60  # seconds

    # Suspicious commands that trigger alerts
    SUSPICIOUS_COMMANDS = [
        "wget", "curl", "nc", "ncat", "netcat",
        "chmod +x", "python -c", "perl -e", "bash -i",
        "/etc/shadow", "/etc/passwd",
        "rm -rf", "mkfs", "dd if=",
        "iptables", "ufw",
        "base64", "eval",
    ]

    # Common attack usernames
    SUSPICIOUS_USERNAMES = [
        "root", "admin", "administrator", "test",
        "oracle", "postgres", "mysql", "ftp",
        "guest", "support", "ubnt", "pi",
    ]

    def __init__(self, log_dir):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        self.connections_file = os.path.join(log_dir, "connections.jsonl")
        self.auth_file = os.path.join(log_dir, "auth_attempts.jsonl")
        self.commands_file = os.path.join(log_dir, "commands.jsonl")
        self.alerts_file = os.path.join(log_dir, "alerts.jsonl")
        self.main_log = os.path.join(log_dir, "honeypot.log")

        # Set up standard Python logging
        self._setup_logging()

        # Tracking for alerts
        self.auth_attempts = defaultdict(list)  # ip -> [timestamps]
        self.lock = threading.Lock()

        self.logger.info("HoneypotLogger initialized")

    def _setup_logging(self):
        """Set up the Python logging framework."""
        self.logger = logging.getLogger("Honeypot")
        self.logger.setLevel(logging.INFO)

        # File handler
        fh = logging.FileHandler(self.main_log)
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.logger.addHandler(fh)

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.logger.addHandler(ch)

    def _write_jsonl(self, filepath, data):
        """Append a JSON record to a JSONL file."""
        try:
            with open(filepath, "a") as f:
                f.write(json.dumps(data) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write to {filepath}: {e}")

    def log_connection(self, source_ip, source_port):
        """Log a new connection."""
        record = {
            "type": "connection",
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "source_port": source_port,
        }
        self._write_jsonl(self.connections_file, record)
        self.logger.info(f"[CONN] New connection from {source_ip}:{source_port}")

    def log_disconnect(self, source_ip, duration):
        """Log a disconnection with session duration."""
        record = {
            "type": "disconnect",
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "duration_seconds": round(duration, 2),
        }
        self._write_jsonl(self.connections_file, record)
        self.logger.info(f"[DISC] {source_ip} disconnected (duration: {duration:.1f}s)")

    def log_auth_attempt(self, source_ip, username, password, attempt_num):
        """Log an authentication attempt and check for brute force."""
        record = {
            "type": "auth_attempt",
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "username": username,
            "password": password,
            "attempt_number": attempt_num,
        }
        self._write_jsonl(self.auth_file, record)
        self.logger.info(f"[AUTH] {source_ip} - user='{username}' pass='{password}' (attempt #{attempt_num})")

        # Track for brute force detection
        self._check_brute_force(source_ip)

        # Check for suspicious usernames
        if username.lower() in self.SUSPICIOUS_USERNAMES:
            self._alert(
                source_ip,
                f"Suspicious username '{username}' (common attack username)",
                "medium",
            )

    def log_command(self, source_ip, username, command):
        """Log a command executed in the fake shell."""
        record = {
            "type": "command",
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "username": username,
            "command": command,
        }
        self._write_jsonl(self.commands_file, record)
        self.logger.info(f"[CMD]  {source_ip} ({username}): {command}")

        # Check for suspicious commands
        cmd_lower = command.lower()
        for suspicious in self.SUSPICIOUS_COMMANDS:
            if suspicious in cmd_lower:
                self._alert(
                    source_ip,
                    f"Suspicious command: '{command}' (matched: '{suspicious}')",
                    "high",
                )
                break

    def log_event(self, event_type, source_ip, message):
        """Log a general event."""
        record = {
            "type": event_type,
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "message": message,
        }
        self._write_jsonl(self.connections_file, record)
        self.logger.info(f"[{event_type.upper()}] {source_ip}: {message}")

    def _check_brute_force(self, source_ip):
        """Check if an IP is performing a brute force attack."""
        with self.lock:
            now = time.time()
            self.auth_attempts[source_ip].append(now)

            # Remove old entries outside the window
            cutoff = now - self.BRUTE_FORCE_WINDOW
            self.auth_attempts[source_ip] = [
                t for t in self.auth_attempts[source_ip] if t > cutoff
            ]

            count = len(self.auth_attempts[source_ip])
            if count >= self.BRUTE_FORCE_THRESHOLD:
                self._alert(
                    source_ip,
                    f"Brute force detected: {count} auth attempts in {self.BRUTE_FORCE_WINDOW}s",
                    "critical",
                )

    def _alert(self, source_ip, message, severity="medium"):
        """Generate a security alert."""
        record = {
            "type": "alert",
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "severity": severity,
            "message": message,
        }
        self._write_jsonl(self.alerts_file, record)
        self.logger.warning(f"[ALERT:{severity.upper()}] {source_ip}: {message}")
