#!/usr/bin/env python3
"""
Port Scanner - Network Security Assignment 2
Custom network scanning tool with multi-threading, banner grabbing,
CIDR support, and multiple output formats.

Features:
- TCP connect scans to detect open ports
- Multi-threaded scanning for fast results
- Banner/service detection on open ports
- CIDR notation support for scanning subnets
- Multiple output formats (text, JSON, CSV)
- Configurable timeout and thread count
- Progress indicator during scans
"""

import argparse
import csv
import io
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# Well-known port-to-service mapping for fallback identification
KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    2222: "SSH (non-standard)",
    3306: "MySQL",
    3389: "RDP",
    5000: "HTTP (Flask/Dev)",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    8888: "HTTP Alt",
    27017: "MongoDB",
}


def grab_banner(target, port, timeout=2.0):
    """
    Attempt to grab a service banner from an open port.

    Args:
        target: IP address or hostname
        port: Port number
        timeout: Socket timeout in seconds

    Returns:
        str: Banner text if available, empty string otherwise
    """
    banner = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # For HTTP-like services, send a GET request
        if port in (80, 443, 5000, 5001, 8080, 8443, 8888):
            sock.sendall(b"GET / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
        elif port == 6379:
            # Redis PING command
            sock.sendall(b"PING\r\n")
        else:
            # For other services, just wait for the banner
            pass

        # Try to receive data
        sock.settimeout(2.0)
        data = sock.recv(4096)
        if data:
            banner = data.decode("utf-8", errors="replace").strip()
            # Truncate long banners
            if len(banner) > 200:
                banner = banner[:200] + "..."
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return banner


def identify_service(port, banner):
    """
    Identify the service running on a port based on banner and port number.

    Args:
        port: Port number
        banner: Banner text grabbed from the service

    Returns:
        str: Identified service name
    """
    if banner:
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            return "SSH"
        elif "http" in banner_lower or "html" in banner_lower:
            return "HTTP"
        elif "mysql" in banner_lower:
            return "MySQL"
        elif "redis" in banner_lower or "+pong" in banner_lower:
            return "Redis"
        elif "ftp" in banner_lower:
            return "FTP"
        elif "smtp" in banner_lower:
            return "SMTP"
        elif "flask" in banner_lower:
            return "HTTP (Flask)"
        elif "secret api" in banner_lower or "api" in banner_lower:
            return "HTTP API"
        elif "json" in banner_lower or "{" in banner:
            return "HTTP/JSON API"

    return KNOWN_SERVICES.get(port, "Unknown")


def scan_port(target, port, timeout=1.5):
    """
    Scan a single port on the target host using TCP connect scan.

    Args:
        target: IP address or hostname to scan
        port: Port number to scan
        timeout: Connection timeout in seconds

    Returns:
        dict or None: Port info dict if open, None if closed
    """
    start_time = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        elapsed = time.time() - start_time
        sock.close()

        if result == 0:
            # Port is open - grab banner
            banner = grab_banner(target, port, timeout=2.0)
            service = identify_service(port, banner)

            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner,
                "response_time_ms": round(elapsed * 1000, 2),
            }
        return None

    except socket.timeout:
        return None
    except ConnectionRefusedError:
        return None
    except OSError:
        return None


def resolve_targets(target_str):
    """
    Resolve target string to list of IP addresses.
    Supports single IP, hostname, and CIDR notation.

    Args:
        target_str: Target string (IP, hostname, or CIDR)

    Returns:
        list: List of IP address strings
    """
    targets = []

    # Check if it's CIDR notation
    if "/" in target_str:
        try:
            network = ipaddress.ip_network(target_str, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        except ValueError:
            print(f"[!] Invalid CIDR notation: {target_str}")
            sys.exit(1)
    else:
        # Single host - resolve hostname if needed
        try:
            ip = socket.gethostbyname(target_str)
            targets = [ip]
        except socket.gaierror:
            print(f"[!] Could not resolve hostname: {target_str}")
            sys.exit(1)

    return targets


def parse_ports(port_str):
    """
    Parse port range string into list of ports.
    Supports: single port, range (1-1024), comma-separated (22,80,443),
    or combination (22,80,100-200).

    Args:
        port_str: Port specification string

    Returns:
        list: List of port numbers
    """
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                if start < 1:
                    start = 1
                if end > 65535:
                    end = 65535
                ports.update(range(start, end + 1))
            except ValueError:
                print(f"[!] Invalid port range: {part}")
                sys.exit(1)
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                print(f"[!] Invalid port: {part}")
                sys.exit(1)

    return sorted(ports)


def scan_host(target, ports, threads=100, timeout=1.5):
    """
    Scan all specified ports on a single host using thread pool.

    Args:
        target: IP address to scan
        ports: List of port numbers
        threads: Number of concurrent threads
        timeout: Socket timeout per port

    Returns:
        list: List of open port info dicts
    """
    open_ports = []
    total = len(ports)
    scanned = 0

    print(f"\n[*] Scanning {target} | {total} ports | {threads} threads | timeout {timeout}s")
    print(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 65)

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            scanned += 1
            result = future.result()

            if result:
                open_ports.append(result)
                port_info = result
                banner_short = (
                    port_info["banner"][:60] + "..."
                    if len(port_info["banner"]) > 60
                    else port_info["banner"]
                )
                print(
                    f"  [+] Port {port_info['port']:>5}/tcp  OPEN  "
                    f"| {port_info['service']:<18} "
                    f"| {port_info['response_time_ms']:.1f}ms"
                )
                if banner_short:
                    print(f"       Banner: {banner_short}")

            # Progress indicator every 10%
            if total > 100 and scanned % (total // 10) == 0:
                pct = (scanned / total) * 100
                elapsed = time.time() - start_time
                print(f"  ... {pct:.0f}% complete ({scanned}/{total}) - {elapsed:.1f}s elapsed")

    elapsed = time.time() - start_time
    print("-" * 65)
    print(f"[*] Scan completed in {elapsed:.2f} seconds")
    print(f"[*] {len(open_ports)} open port(s) found on {target}")

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def format_text(results):
    """Format results as human-readable text table."""
    lines = []
    lines.append("")
    lines.append("=" * 75)
    lines.append("  PORT SCAN RESULTS")
    lines.append("=" * 75)

    for host, ports in results.items():
        lines.append(f"\n  Host: {host}")
        lines.append(f"  Open ports: {len(ports)}")
        lines.append(f"  {'PORT':<10} {'STATE':<8} {'SERVICE':<20} {'RESPONSE':<10}")
        lines.append("  " + "-" * 55)

        for p in ports:
            lines.append(
                f"  {p['port']:<10} {p['state']:<8} {p['service']:<20} "
                f"{p['response_time_ms']:.1f}ms"
            )
            if p["banner"]:
                banner = p["banner"][:70]
                lines.append(f"    Banner: {banner}")

    lines.append("\n" + "=" * 75)
    return "\n".join(lines)


def format_json(results):
    """Format results as JSON."""
    output = {
        "scan_time": datetime.now().isoformat(),
        "hosts": {},
    }
    for host, ports in results.items():
        output["hosts"][host] = {
            "open_ports": len(ports),
            "ports": ports,
        }
    return json.dumps(output, indent=2)


def format_csv(results):
    """Format results as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["host", "port", "state", "service", "banner", "response_time_ms"])
    for host, ports in results.items():
        for p in ports:
            writer.writerow(
                [host, p["port"], p["state"], p["service"], p["banner"], p["response_time_ms"]]
            )
    return output.getvalue()


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Port Scanner - Network Security Assignment 2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 -m port_scanner --target 172.20.0.10 --ports 1-10000
  python3 -m port_scanner --target 172.20.0.0/24 --ports 1-10000 --threads 200
  python3 -m port_scanner --target webapp --ports 1-65535 --threads 100
  python3 -m port_scanner --target 172.20.0.20 --ports 2222 --format json
        """,
    )
    parser.add_argument(
        "--target", "-t", required=True, help="Target IP, hostname, or CIDR (e.g., 172.20.0.0/24)"
    )
    parser.add_argument(
        "--ports", "-p", default="1-10000", help="Port range (default: 1-10000). Examples: 1-1024, 22,80,443, 1-65535"
    )
    parser.add_argument(
        "--threads", "-T", type=int, default=100, help="Number of threads (default: 100)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.5, help="Socket timeout in seconds (default: 1.5)"
    )
    parser.add_argument(
        "--format", "-f", choices=["text", "json", "csv"], default="text", help="Output format (default: text)"
    )
    parser.add_argument(
        "--output", "-o", help="Output file path (default: stdout)"
    )
    return parser.parse_args()


def main():
    """Main entry point for the port scanner."""
    args = parse_args()

    print("=" * 65)
    print("  PORT SCANNER - Network Security Assignment 2")
    print("=" * 65)

    # Resolve targets
    targets = resolve_targets(args.target)
    ports = parse_ports(args.ports)

    print(f"[*] Target(s): {args.target} ({len(targets)} host(s))")
    print(f"[*] Ports: {args.ports} ({len(ports)} ports)")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Timeout: {args.timeout}s")

    # Scan each host
    all_results = {}
    for target in targets:
        host_results = scan_host(target, ports, args.threads, args.timeout)
        if host_results:
            all_results[target] = host_results

    # Format output
    if args.format == "json":
        output = format_json(all_results)
    elif args.format == "csv":
        output = format_csv(all_results)
    else:
        output = format_text(all_results)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"\n[*] Results saved to {args.output}")
    else:
        print(output)

    # Summary
    total_open = sum(len(ports) for ports in all_results.values())
    print(f"\n[*] Total: {total_open} open port(s) across {len(all_results)} host(s)")


if __name__ == "__main__":
    main()
