#!/usr/bin/env python3
"""
SSH Honeypot
Assignment 2: Network Security

Simulates a realistic SSH server to attract and log unauthorized access
attempts. All interactions are logged for analysis.

Features:
- Realistic SSH banner and authentication flow
- Logs all connection attempts with timestamps and source IPs
- Records usernames and passwords attempted
- Simulates a fake shell with common commands
- Alerts on suspicious activity (brute force, known attack patterns)
- JSON-structured logging for easy analysis
"""

import json
import logging
import os
import socket
import sys
import threading
import time
from datetime import datetime

from logger import HoneypotLogger

# Configuration
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 22
SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
MAX_AUTH_ATTEMPTS = 3
LOG_DIR = "/app/logs"

# Fake filesystem for shell simulation
FAKE_FS = {
    "/": ["bin", "etc", "home", "root", "tmp", "var", "usr"],
    "/home": ["admin", "user"],
    "/home/admin": [".ssh", "documents", ".bash_history"],
    "/home/admin/documents": ["credentials.txt", "backup.tar.gz"],
    "/etc": ["passwd", "shadow", "hosts", "ssh"],
    "/root": [".ssh", "admin_notes.txt"],
    "/tmp": [],
    "/var": ["log", "www"],
    "/var/log": ["auth.log", "syslog"],
}

FAKE_FILES = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "admin:x:1000:1000:Admin User:/home/admin:/bin/bash\n"
        "user:x:1001:1001:Regular User:/home/user:/bin/bash\n"
    ),
    "/etc/hosts": "127.0.0.1\tlocalhost\n172.20.0.10\twebapp\n172.20.0.11\tdatabase\n",
    "/home/admin/documents/credentials.txt": "admin:admin123\nroot:toor\nuser:password\n",
    "/root/admin_notes.txt": "TODO: Change default passwords\nDB backup scheduled for midnight\n",
}


class FakeShell:
    """Simulates a basic shell environment for the honeypot."""

    def __init__(self, logger, client_ip, username):
        self.logger = logger
        self.client_ip = client_ip
        self.username = username
        self.cwd = f"/home/{username}" if username != "root" else "/root"
        self.hostname = "ubuntu-server"

    def get_prompt(self):
        user_part = self.username
        if self.username == "root":
            return f"root@{self.hostname}:{self.cwd}# "
        return f"{user_part}@{self.hostname}:{self.cwd}$ "

    def handle_command(self, cmd):
        """Process a command and return fake output."""
        cmd = cmd.strip()
        if not cmd:
            return ""

        self.logger.log_command(self.client_ip, self.username, cmd)

        parts = cmd.split()
        base_cmd = parts[0]

        if base_cmd == "ls":
            return self._cmd_ls(parts)
        elif base_cmd == "pwd":
            return self.cwd + "\n"
        elif base_cmd == "cd":
            return self._cmd_cd(parts)
        elif base_cmd == "cat":
            return self._cmd_cat(parts)
        elif base_cmd == "whoami":
            return self.username + "\n"
        elif base_cmd == "id":
            if self.username == "root":
                return "uid=0(root) gid=0(root) groups=0(root)\n"
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})\n"
        elif base_cmd == "uname":
            return "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
        elif base_cmd == "hostname":
            return self.hostname + "\n"
        elif base_cmd in ("exit", "quit", "logout"):
            return None  # Signal to close connection
        elif base_cmd == "wget" or base_cmd == "curl":
            return f"bash: {base_cmd}: command not found\n"
        elif base_cmd == "sudo":
            return f"[sudo] password for {self.username}: \n"
        elif base_cmd == "ifconfig" or base_cmd == "ip":
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 172.20.0.30  netmask 255.255.0.0  broadcast 172.20.255.255\n"
            )
        elif base_cmd == "ps":
            return (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:02 sshd\n"
                " 1234 pts/0    00:00:00 bash\n"
                f" 1235 pts/0    00:00:00 {base_cmd}\n"
            )
        elif base_cmd in ("rm", "mv", "cp", "chmod", "chown"):
            return ""  # Silently "succeed"
        elif base_cmd == "echo":
            return " ".join(parts[1:]) + "\n"
        elif base_cmd == "history":
            return (
                "    1  ls\n"
                "    2  cd /home\n"
                "    3  cat /etc/passwd\n"
            )
        else:
            return f"bash: {base_cmd}: command not found\n"

    def _cmd_ls(self, parts):
        target = self.cwd if len(parts) == 1 else parts[1]
        if not target.startswith("/"):
            target = self.cwd.rstrip("/") + "/" + target

        items = FAKE_FS.get(target)
        if items is not None:
            return "  ".join(items) + "\n" if items else ""
        return f"ls: cannot access '{parts[1] if len(parts) > 1 else ''}': No such file or directory\n"

    def _cmd_cd(self, parts):
        if len(parts) == 1:
            self.cwd = f"/home/{self.username}" if self.username != "root" else "/root"
            return ""
        target = parts[1]
        if not target.startswith("/"):
            target = self.cwd.rstrip("/") + "/" + target

        if target in FAKE_FS:
            self.cwd = target
            return ""
        return f"bash: cd: {parts[1]}: No such file or directory\n"

    def _cmd_cat(self, parts):
        if len(parts) < 2:
            return ""
        filepath = parts[1]
        if not filepath.startswith("/"):
            filepath = self.cwd.rstrip("/") + "/" + filepath

        content = FAKE_FILES.get(filepath)
        if content:
            return content
        return f"cat: {parts[1]}: No such file or directory\n"


class SSHHoneypot:
    """Main SSH honeypot server."""

    def __init__(self, host=LISTEN_HOST, port=LISTEN_PORT):
        self.host = host
        self.port = port
        self.logger = HoneypotLogger(LOG_DIR)
        self.running = True

    def start(self):
        """Start the honeypot server."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.settimeout(1.0)

        try:
            server_sock.bind((self.host, self.port))
            server_sock.listen(10)
            self.logger.log_event("server", "0.0.0.0", f"Honeypot listening on {self.host}:{self.port}")
            print(f"[*] SSH Honeypot listening on {self.host}:{self.port}")
        except OSError as e:
            print(f"[!] Cannot bind to {self.host}:{self.port}: {e}")
            sys.exit(1)

        while self.running:
            try:
                client_sock, addr = server_sock.accept()
                client_ip = addr[0]
                client_port = addr[1]

                self.logger.log_connection(client_ip, client_port)
                print(f"[+] Connection from {client_ip}:{client_port}")

                # Handle in a new thread
                t = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, client_ip, client_port),
                    daemon=True,
                )
                t.start()

            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.log_event("error", "0.0.0.0", str(e))

        server_sock.close()
        print("[*] Honeypot stopped")

    def handle_client(self, client_sock, client_ip, client_port):
        """Handle a single client connection."""
        start_time = time.time()
        authenticated_user = None

        try:
            client_sock.settimeout(30.0)

            # Send SSH banner
            client_sock.sendall(SSH_BANNER)

            # Wait for client SSH banner
            try:
                client_banner = client_sock.recv(1024)
                if client_banner:
                    banner_str = client_banner.decode("utf-8", errors="replace").strip()
                    self.logger.log_event("client_banner", client_ip, banner_str)
            except Exception:
                pass

            # Simulate SSH authentication
            authenticated_user = self._handle_auth(client_sock, client_ip)

            if authenticated_user:
                # Run fake shell
                self._handle_shell(client_sock, client_ip, authenticated_user)

        except socket.timeout:
            self.logger.log_event("timeout", client_ip, "Connection timed out")
        except ConnectionResetError:
            self.logger.log_event("disconnect", client_ip, "Connection reset by peer")
        except BrokenPipeError:
            self.logger.log_event("disconnect", client_ip, "Broken pipe")
        except Exception as e:
            self.logger.log_event("error", client_ip, str(e))
        finally:
            duration = time.time() - start_time
            self.logger.log_disconnect(client_ip, duration)
            try:
                client_sock.close()
            except Exception:
                pass

    def _handle_auth(self, client_sock, client_ip):
        """Simulate SSH password authentication.
        Returns username if 'authenticated', None otherwise.
        """
        for attempt in range(MAX_AUTH_ATTEMPTS):
            try:
                # Send username prompt
                client_sock.sendall(b"\r\nlogin as: ")
                username_data = client_sock.recv(1024)
                if not username_data:
                    return None
                username = username_data.decode("utf-8", errors="replace").strip()

                # Send password prompt
                client_sock.sendall(f"{username}@server's password: ".encode())
                password_data = client_sock.recv(1024)
                if not password_data:
                    return None
                password = password_data.decode("utf-8", errors="replace").strip()

                # Log the attempt
                self.logger.log_auth_attempt(client_ip, username, password, attempt + 1)
                print(f"  [AUTH] {client_ip} - {username}:{password} (attempt {attempt + 1})")

                # Always "accept" on the last attempt to keep them engaged
                if attempt == MAX_AUTH_ATTEMPTS - 1:
                    client_sock.sendall(b"\r\nWelcome to Ubuntu 22.04.3 LTS\r\n\r\n")
                    self.logger.log_event(
                        "auth_success", client_ip,
                        f"Accepted login as '{username}' (honeypot - always accepts on last try)"
                    )
                    return username
                else:
                    client_sock.sendall(b"\r\nPermission denied, please try again.\r\n")
                    time.sleep(1)  # Realistic delay

            except Exception:
                return None

        return None

    def _handle_shell(self, client_sock, client_ip, username):
        """Provide a fake interactive shell."""
        shell = FakeShell(self.logger, client_ip, username)

        try:
            # Send initial shell prompt
            prompt = shell.get_prompt()
            client_sock.sendall(prompt.encode())

            while True:
                data = client_sock.recv(4096)
                if not data:
                    break

                command = data.decode("utf-8", errors="replace").strip()
                if not command:
                    client_sock.sendall(prompt.encode())
                    continue

                output = shell.handle_command(command)

                if output is None:
                    # Exit command
                    client_sock.sendall(b"logout\r\n")
                    break

                response = output + prompt
                client_sock.sendall(response.encode())

        except Exception:
            pass


def main():
    print("=" * 50)
    print("  SSH Honeypot - Network Security Assignment 2")
    print("=" * 50)

    honeypot = SSHHoneypot(LISTEN_HOST, LISTEN_PORT)
    honeypot.start()


if __name__ == "__main__":
    main()
