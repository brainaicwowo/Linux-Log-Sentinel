# 🛡️ Linux Log Sentinel

### Real-Time SSH Brute-Force Detection & Automated IP Blocking System

**Linux Log Sentinel** is a Python-based security monitoring tool that continuously monitors Linux authentication logs to detect suspicious SSH login activities and potential brute-force attempts.

It identifies repeated failed login attempts, tracks suspicious IP addresses, and automatically applies temporary firewall blocks. It also generates structured JSON alerts that can be used for security monitoring and log analysis.

---

## 📌 Project Overview

SSH brute-force attacks involve repeated login attempts to gain unauthorized access to a Linux system.

Linux Log Sentinel helps detect this activity by monitoring authentication logs in real time.

When an IP address exceeds the configured failed-login threshold, the system:

1. Detects repeated failed SSH login attempts.
2. Identifies the source IP address and targeted username.
3. Checks whether the IP address is whitelisted.
4. Automatically blocks suspicious IP addresses.
5. Generates structured JSON security alerts.
6. Automatically removes the temporary firewall block after the configured duration.

---

## ✨ Key Features

- **Real-Time Log Monitoring:** Continuously monitors Linux authentication logs for failed SSH login attempts.
- **Brute-Force Detection:** Detects repeated failed login attempts using regular expressions.
- **IP Address Tracking:** Tracks failed login attempts from individual source IP addresses.
- **Configurable Detection Threshold:** Allows users to configure the number of failed attempts and monitoring time window.
- **Automated IP Blocking:** Uses Linux firewall rules to temporarily block suspicious IP addresses.
- **Automatic IP Unblocking:** Removes temporary firewall blocks after the configured ban duration.
- **IP Whitelisting:** Prevents specified trusted IP addresses from being automatically blocked.
- **JSON Security Alerts:** Generates structured JSON alerts containing attack-related information.
- **SIEM-Friendly Logging:** Stores security events in a format suitable for further log analysis.

---

## 🛠️ Technology Stack

| Technology                  | Purpose                             |
| --------------------------- | ----------------------------------- |
| Python 3                    | Main programming language           |
| Regular Expressions (Regex) | Detecting failed SSH login patterns |
| Linux Authentication Logs   | Source of security events           |
| iptables                    | Firewall rule management            |
| JSON                        | Structured security alert storage   |
| Linux                       | Operating system environment        |

---

## 📂 Project Structure

```text
Linux-Log-Sentinel/
│
├── sentinel.py       # Main detection and monitoring script
├── alerts.json       # Generated security alerts
├── .gitignore        # Git ignore configuration
└── README.md         # Project documentation
```

---

## ⚙️ Requirements

Before running the project, make sure you have:

- A Linux-based operating system.
- Python 3 installed.
- iptables available on the system.
- Root privileges (required for firewall rule management).
- Access to the Linux authentication log file.

**Note:** The default authentication log path is `/var/log/auth.log`. On RHEL-based distributions such as CentOS and RHEL, the path is commonly `/var/log/secure`.

---

## 🚀 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/brainaicwowo/Linux-Log-Sentinel.git
```

### 2. Navigate to the Project Directory

```bash
cd Linux-Log-Sentinel
```

### 3. Check Python Version

```bash
python3 --version
```

### 4. Check Firewall Availability

```bash
sudo iptables --version
```

No external Python packages are required. The script uses Python standard-library modules.

---

## ▶️ Usage

Run the script with root privileges:

```bash
sudo python3 sentinel.py
```

The default configuration is:

| Parameter                | Default Value       |
| ------------------------ | ------------------- |
| Authentication Log       | `/var/log/auth.log` |
| Failed Attempt Threshold | 3 attempts          |
| Detection Time Window    | 60 seconds          |
| IP Ban Duration          | 30 seconds          |
| JSON Alert File          | `alerts.json`       |
| Default Whitelisted IP   | `10.0.0.1`          |

### Custom Configuration

You can customize the detection settings using command-line arguments.

```bash
sudo python3 sentinel.py \
  --log /var/log/auth.log \
  --threshold 5 \
  --window 60 \
  --ban-time 120 \
  --whitelist 127.0.0.1
```

### Available Command-Line Arguments

| Argument      | Description                               |
| ------------- | ----------------------------------------- |
| `--log`       | Authentication log file path              |
| `--json`      | JSON alert output file                    |
| `--threshold` | Number of failed attempts before blocking |
| `--window`    | Detection time window in seconds          |
| `--ban-time`  | IP blocking duration in seconds           |
| `--whitelist` | List of trusted IP addresses              |

**Important:** Setting `--ban-time 0` disables automatic unblocking, resulting in a persistent firewall rule that must be managed separately.

---

## 📊 Security Alert Format

Whenever a suspicious IP address is blocked, Linux Log Sentinel generates a structured JSON alert.

Example:

```json
{
  "@timestamp": "2026-11-06T10:30:00+00:00",
  "event_type": "ssh_brute_force_detected",
  "source_ip": "192.168.1.50",
  "target_user": "admin",
  "failed_attempts": 3,
  "time_window_seconds": 60,
  "action_taken": "iptables_drop",
  "ban_duration_seconds": 30
}
```

The alert contains information about:

- Detection timestamp
- Event type
- Suspicious source IP
- Targeted username
- Number of failed attempts
- Detection time window
- Firewall action
- Blocking duration

---

## 🔮 Future Improvements

- Add email notifications for detected security events.
- Develop a web-based monitoring dashboard.
- Integrate with Elasticsearch and the ELK Stack.
- Add support for additional authentication attack patterns.
- Implement persistent IP tracking across program restarts.
- Add graphical reports and security statistics.

---
## 👨‍💻 Author

**Prathamesh Shingade**
- LinkedIn: [Prathamesh Shingade](https://linkedin.com/in/prathameshshingade)

---

⭐ If you find this project useful, consider giving the repository a star!

**Built with Python and Linux for practical defensive cybersecurity monitoring.**
