#!/usr/bin/env python3
"""
Port Knocking Server
Assignment 2: Network Security

Listens for a specific sequence of TCP connection attempts (knocks) on
predefined ports. When the correct sequence is received from a source IP
within the configured time window, the protected port is opened via
iptables for that IP address.

Features:
- Configurable knock sequence and timing window
- iptables-based firewall rules to open/close protected port
- Per-source-IP tracking with automatic timeout
- Reset on incorrect sequence
- Logging of all knock attempts
"""

import argparse
import logging
import os
import socket
import subprocess
import threading
import time
from collections import defaultdict

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 15.0
DEFAULT_ACCESS_DURATION = 30.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


class KnockTracker:
    """Track knock sequence progress per source IP."""

    def __init__(self, sequence, window_seconds):
        self.sequence = sequence
        self.window = window_seconds
        self.progress = {}  # ip -> {"step": int, "start_time": float}
        self.lock = threading.Lock()

    def register_knock(self, source_ip, knock_port):
        """Register a knock from a source IP on a specific port.

        Returns True if the full sequence is completed.
        """
        with self.lock:
            now = time.time()

            if source_ip not in self.progress:
                # First knock - must be the first port in the sequence
                if knock_port == self.sequence[0]:
                    self.progress[source_ip] = {"step": 1, "start_time": now}
                    logging.info(
                        f"[KNOCK] {source_ip} started sequence (step 1/{len(self.sequence)}) "
                        f"on port {knock_port}"
                    )
                else:
                    logging.info(
                        f"[KNOCK] {source_ip} knocked on wrong port {knock_port} "
                        f"(expected {self.sequence[0]})"
                    )
                return False

            state = self.progress[source_ip]
            elapsed = now - state["start_time"]

            # Check timing window
            if elapsed > self.window:
                logging.warning(
                    f"[KNOCK] {source_ip} sequence timed out "
                    f"({elapsed:.1f}s > {self.window}s). Resetting."
                )
                del self.progress[source_ip]
                # Re-check if this knock starts a new sequence
                if knock_port == self.sequence[0]:
                    self.progress[source_ip] = {"step": 1, "start_time": now}
                return False

            expected_port = self.sequence[state["step"]]

            if knock_port == expected_port:
                state["step"] += 1
                logging.info(
                    f"[KNOCK] {source_ip} correct knock "
                    f"(step {state['step']}/{len(self.sequence)}) on port {knock_port}"
                )

                if state["step"] == len(self.sequence):
                    # Sequence complete!
                    del self.progress[source_ip]
                    logging.info(
                        f"[KNOCK] {source_ip} completed full sequence in {elapsed:.1f}s!"
                    )
                    return True
            else:
                logging.warning(
                    f"[KNOCK] {source_ip} wrong port {knock_port} "
                    f"(expected {expected_port}). Resetting."
                )
                del self.progress[source_ip]

            return False


def open_protected_port(source_ip, protected_port):
    """Open the protected port for a specific source IP using iptables."""
    logger = logging.getLogger("Firewall")
    try:
        # Add iptables rule to allow access from this IP
        cmd = [
            "iptables", "-I", "INPUT", "1",
            "-s", source_ip,
            "-p", "tcp",
            "--dport", str(protected_port),
            "-j", "ACCEPT",
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        logger.info(f"OPENED port {protected_port} for {source_ip}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to open port: {e}")
        return False
    except FileNotFoundError:
        logger.warning("iptables not found - running in demo mode (no real firewall changes)")
        return True


def close_protected_port(source_ip, protected_port):
    """Close the protected port for a specific source IP."""
    logger = logging.getLogger("Firewall")
    try:
        cmd = [
            "iptables", "-D", "INPUT",
            "-s", source_ip,
            "-p", "tcp",
            "--dport", str(protected_port),
            "-j", "ACCEPT",
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        logger.info(f"CLOSED port {protected_port} for {source_ip}")
    except subprocess.CalledProcessError:
        pass  # Rule may not exist
    except FileNotFoundError:
        logger.warning("iptables not found - demo mode")


def setup_default_firewall(protected_port):
    """Set up initial iptables rules to block the protected port."""
    logger = logging.getLogger("Firewall")
    try:
        # Drop all incoming connections to the protected port by default
        cmd = [
            "iptables", "-A", "INPUT",
            "-p", "tcp",
            "--dport", str(protected_port),
            "-j", "DROP",
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        logger.info(f"Default firewall: port {protected_port} is BLOCKED")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set up default firewall: {e}")
    except FileNotFoundError:
        logger.warning("iptables not found - running in demo mode")


def handle_knock_connection(sock, knock_port, tracker, protected_port, access_duration):
    """Handle an incoming connection on a knock port."""
    try:
        conn, addr = sock.accept()
        source_ip = addr[0]
        conn.close()

        # Register the knock
        sequence_complete = tracker.register_knock(source_ip, knock_port)

        if sequence_complete:
            # Open the protected port for this IP
            if open_protected_port(source_ip, protected_port):
                logging.info(
                    f"[ACCESS] Port {protected_port} opened for {source_ip} "
                    f"for {access_duration}s"
                )

                # Schedule port closure after the access duration
                def close_later():
                    time.sleep(access_duration)
                    close_protected_port(source_ip, protected_port)
                    logging.info(
                        f"[ACCESS] Port {protected_port} access expired for {source_ip}"
                    )

                t = threading.Thread(target=close_later, daemon=True)
                t.start()

    except OSError:
        pass


def listen_on_port(port, tracker, protected_port, access_duration):
    """Listen for knock connections on a single port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)

    try:
        sock.bind(("0.0.0.0", port))
        sock.listen(5)
        logging.info(f"Listening for knocks on port {port}")
    except OSError as e:
        logging.error(f"Cannot bind to port {port}: {e}")
        return

    while True:
        try:
            handle_knock_connection(sock, port, tracker, protected_port, access_duration)
        except socket.timeout:
            continue
        except Exception as e:
            logging.error(f"Error on port {port}: {e}")
            time.sleep(0.1)


def listen_for_knocks(sequence, window_seconds, protected_port, access_duration):
    """Start listeners on all knock ports."""
    logger = logging.getLogger("KnockServer")
    logger.info(f"Port Knocking Server Starting")
    logger.info(f"Knock sequence: {sequence}")
    logger.info(f"Protected port: {protected_port}")
    logger.info(f"Time window: {window_seconds}s")
    logger.info(f"Access duration: {access_duration}s")

    # Set up default firewall to block protected port
    setup_default_firewall(protected_port)

    tracker = KnockTracker(sequence, window_seconds)

    # Start a listener thread for each knock port
    threads = []
    for port in sequence:
        t = threading.Thread(
            target=listen_on_port,
            args=(port, tracker, protected_port, access_duration),
            daemon=True,
        )
        t.start()
        threads.append(t)

    logger.info("All knock port listeners started. Waiting for knocks...")

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Server shutting down...")


def parse_args():
    parser = argparse.ArgumentParser(description="Port Knocking Server")
    parser.add_argument(
        "--sequence",
        default=",".join(str(p) for p in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports (default: 1234,5678,9012)",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port (default: 2222)",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence (default: 15)",
    )
    parser.add_argument(
        "--access-duration",
        type=float,
        default=DEFAULT_ACCESS_DURATION,
        help="Seconds to keep port open after successful knock (default: 30)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(p) for p in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port, args.access_duration)


if __name__ == "__main__":
    main()
