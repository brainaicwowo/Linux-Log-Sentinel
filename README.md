# Linux Log Sentinel & Brute-Force Detector 🛡️

A real-time Python and Bash security daemon that monitors Linux authentication logs (`/var/log/auth.log`), detects SSH brute-force patterns using Regex, and automatically mitigates attack vectors using dynamic `iptables` rule injection.

## Features
- **Real-Time Log Parsing:** Tails system logs live using Python regex patterns.
- **Automated Active Defense:** Dynamically injects `iptables DROP` rules to block malicious IP addresses exceeding customizable failure thresholds.
- **SIEM Integration:** Writes structured JSON alerts (`alerts.json`) with ISO-8601 UTC timestamps formatted for Splunk or Elastic/ELK stack ingestion.
- **Auto-Unblock Cooldown:** Employs asynchronous threading timers to automatically release blocked IPs after a configurable ban duration.
- **IP Whitelisting:** Built-in safeguards to prevent lockouts on trusted internal subnets.
- **Systemd Daemon Support:** Runs continuously as a background Linux system service.

## Architecture & Workflow

```text
[ /var/log/auth.log ] ---> [ Sentinel Engine ] ---> [ Threshold Check ] ---> [ iptables DROP ]
                                   |
                                   +---------------------------------------> [ SIEM alerts.json ]
