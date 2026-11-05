#!/usr/bin/env python3
import time
import re
import os
import sys
import json
import logging
import argparse
import subprocess
from datetime import datetime
from threading import Timer
from collections import defaultdict
from datetime import datetime, timezone

# Setup basic logging to console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

class Sentinel:
    def __init__(self, log_file, alert_json, threshold, window, ban_time, whitelist):
        self.log_file = log_file
        self.alert_json = alert_json
        self.threshold = threshold
        self.window = window
        self.ban_time = ban_time
        self.whitelist = set(whitelist)
        
        # In-memory tracking
        self.failed_attempts = defaultdict(list)
        self.blocked_ips = set()
        
        # Regex matching failed SSH attempts
        self.fail_pattern = re.compile(
            r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})"
        )

    def write_json_alert(self, ip, username, attempt_count):
        """Enhancement 3: Write structured JSON alert for SIEM/Log Analyzers."""
        alert_data = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "ssh_brute_force_detected",
            "source_ip": ip,
            "target_user": username,
            "failed_attempts": attempt_count,
            "time_window_seconds": self.window,
            "action_taken": "iptables_drop",
            "ban_duration_seconds": self.ban_time
        }
        
        try:
            with open(self.alert_json, "a") as f:
                f.write(json.dumps(alert_data) + "\n")
            logging.info(f"SIEM Alert logged to {self.alert_json}")
        except Exception as e:
            logging.error(f"Failed to write JSON alert: {e}")

    def unblock_ip(self, ip):
        """Enhancement 1: Automatic unblock rule execution after cooldown."""
        logging.info(f"Ban duration ({self.ban_time}s) expired for IP: {ip}. Unblocking...")
        try:
            subprocess.run(f"iptables -D INPUT -s {ip} -j DROP", shell=True, check=True)
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            logging.info(f"SUCCESS: IP {ip} successfully unblocked.")
        except Exception as e:
            logging.error(f"Failed to unblock IP {ip}: {e}")

    def block_ip(self, ip, username, attempt_count):
        """Executes iptables block, triggers JSON logging, and schedules auto-unblock."""
        # Enhancement 2: Check IP Whitelist
        if ip in self.whitelist:
            logging.warning(f"IP {ip} exceeded threshold but is WHITELISTED. Skipping firewall block.")
            return

        if ip in self.blocked_ips:
            return

        logging.error(f"THREAT DETECTED: Blocking IP {ip} via iptables...")
        try:
            # Check if rule already exists
            check_cmd = f"iptables -C INPUT -s {ip} -j DROP"
            result = subprocess.run(check_cmd, shell=True, stderr=subprocess.DEVNULL)

            if result.returncode != 0:
                # Add firewall block rule
                subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
                self.blocked_ips.add(ip)
                logging.info(f"SUCCESS: IP {ip} blocked.")
                
                # Write SIEM JSON Log Entry
                self.write_json_alert(ip, username, attempt_count)

                # Schedule Auto-Unblock Cooldown Timer
                if self.ban_time > 0:
                    t = Timer(self.ban_time, self.unblock_ip, args=[ip])
                    t.daemon = True
                    t.start()
                    logging.info(f"Auto-unblock timer set for IP {ip} in {self.ban_time} seconds.")
        except Exception as e:
            logging.error(f"Error executing iptables block for {ip}: {e}")

    def process_line(self, line):
        """Processes individual log entries in real time."""
        match = self.fail_pattern.search(line)
        if match:
            username, ip = match.groups()
            now = time.time()

            # Clean out timestamps outside the rolling time window
            self.failed_attempts[ip] = [t for t in self.failed_attempts[ip] if now - t <= self.window]
            self.failed_attempts[ip].append(now)

            attempt_count = len(self.failed_attempts[ip])
            logging.warning(f"Failed SSH login for user '{username}' from IP: {ip} ({attempt_count}/{self.threshold})")

            if attempt_count >= self.threshold:
                self.block_ip(ip, username, attempt_count)

    def start(self):
        """Main loop to tail authentication log file."""
        if not os.path.exists(self.log_file):
            logging.error(f"Log file {self.log_file} does not exist.")
            sys.exit(1)

        logging.info(f"Starting Linux Log Sentinel...")
        logging.info(f"Monitoring: {self.log_file}")
        logging.info(f"Threshold: {self.threshold} attempts in {self.window}s | Ban Duration: {self.ban_time}s")
        logging.info(f"Whitelisted IPs: {list(self.whitelist)}")

        with open(self.log_file, "r") as f:
            f.seek(0, os.SEEK_END)  # Start at end of file for live logs
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                self.process_line(line)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] This script requires root privileges to manipulate iptables. Run with sudo.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Linux Log Sentinel & Brute-Force Detector")
    parser.add_argument("--log", default="/var/log/auth.log", help="Path to auth log file")
    parser.add_argument("--json", default="alerts.json", help="Path to output SIEM JSON log")
    parser.add_argument("--threshold", type=int, default=3, help="Failed attempt threshold")
    parser.add_argument("--window", type=int, default=60, help="Time window in seconds")
    parser.add_argument("--ban-time", type=int, default=30, help="Ban duration in seconds (0 for permanent)")
    parser.add_argument("--whitelist", nargs="*", default=["10.0.0.1"], help="List of whitelisted IPs")

    args = parser.parse_args()

    sentinel = Sentinel(
        log_file=args.log,
        alert_json=args.json,
        threshold=args.threshold,
        window=args.window,
        ban_time=args.ban_time,
        whitelist=args.whitelist
    )
    sentinel.start()
