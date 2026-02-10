#!/usr/bin/env python3
"""
Port Knocking Client
Assignment 2: Network Security

Sends a sequence of TCP connection attempts to predefined ports in order
to unlock a protected service on the target host.

Usage:
    python3 knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012
    python3 knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012 --check
"""

import argparse
import socket
import sys
import time

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_DELAY = 0.5


def send_knock(target, port, delay):
    """Send a single TCP knock to the target port.

    A 'knock' is simply a TCP connection attempt. The server detects
    the incoming SYN and records it. Whether the connection succeeds
    or is refused doesn't matter - the server sees the attempt.
    """
    print(f"  [*] Knocking on port {port}...", end=" ")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        sock.connect_ex((target, port))
        sock.close()
        print("done")
    except OSError:
        print("sent (connection refused - expected)")

    time.sleep(delay)


def perform_knock_sequence(target, sequence, delay):
    """Send the full knock sequence to the target."""
    print(f"\n[*] Performing knock sequence on {target}")
    print(f"[*] Sequence: {' -> '.join(str(p) for p in sequence)}")
    print(f"[*] Delay between knocks: {delay}s")
    print()

    start = time.time()
    for i, port in enumerate(sequence, 1):
        print(f"  Step {i}/{len(sequence)}:")
        send_knock(target, port, delay)

    elapsed = time.time() - start
    print(f"\n[+] Knock sequence completed in {elapsed:.2f}s")


def check_protected_port(target, protected_port):
    """Try connecting to the protected port after knocking."""
    print(f"\n[*] Checking if protected port {protected_port} is now open...")
    time.sleep(0.5)  # Brief pause to let server process

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        result = sock.connect_ex((target, protected_port))

        if result == 0:
            # Try to read banner
            try:
                sock.settimeout(2.0)
                banner = sock.recv(1024).decode("utf-8", errors="replace")
                print(f"[+] SUCCESS! Port {protected_port} is OPEN")
                if banner:
                    print(f"[+] Banner: {banner.strip()[:200]}")
            except Exception:
                print(f"[+] SUCCESS! Port {protected_port} is OPEN")
        else:
            print(f"[-] Port {protected_port} is still closed (code: {result})")

        sock.close()
    except socket.timeout:
        print(f"[-] Connection to port {protected_port} timed out")
    except ConnectionRefusedError:
        print(f"[-] Connection to port {protected_port} refused")
    except OSError as e:
        print(f"[-] Could not connect to port {protected_port}: {e}")


def parse_args():
    parser = argparse.ArgumentParser(description="Port Knocking Client")
    parser.add_argument(
        "--target", required=True, help="Target host or IP address"
    )
    parser.add_argument(
        "--sequence",
        default=",".join(str(p) for p in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock port sequence (default: 1234,5678,9012)",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port to check after knocking (default: 2222)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Delay between knocks in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Attempt connection to protected port after knocking",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        sequence = [int(p) for p in args.sequence.split(",")]
    except ValueError:
        print("[!] Invalid sequence. Use comma-separated integers.")
        sys.exit(1)

    print("=" * 50)
    print("  Port Knocking Client")
    print("=" * 50)

    perform_knock_sequence(args.target, sequence, args.delay)

    if args.check:
        check_protected_port(args.target, args.protected_port)

    print("\n[*] Done.")


if __name__ == "__main__":
    main()
