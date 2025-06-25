# BotNetProbe 📡

A PHP tool that parses **network logs in CSV format** and looks for **botnet-like behavior** — such as repeated connections to the same IP/port, burst activity, or unusual outbound patterns.

## 🎯 Why I built this

In red-blue simulations and CEH-style assessments, botnet traffic often mimics patterns like:
- Fast repeated connections to a C2 server
- Suspicious persistence over rare ports
- High-frequency activity from a single source IP

BotNetProbe helps defenders detect these anomalies quickly.

## 📘 Log Format (CSV Required)

```
timestamp,src_ip,dst_ip,port,protocol
2025-06-22 14:11:00,192.168.1.5,203.0.113.5,8080,TCP
2025-06-22 14:11:05,192.168.1.5,203.0.113.5,8080,TCP
...
```

## 🛠 How to use

```bash
php botnetprobe.php netlog.csv
```

## 🚨 Output Example

```
📡 Scanning network log: netlog.csv

🚨 Potential Botnet Behavior Detected:
[ALERT] 192.168.1.5 → 203.0.113.5:8080 [TCP] → 8 bursts
```

## 🧠 Use Cases

- Detect beaconing/bot behavior in SIEM-exported logs
- Triage lateral movement or external callbacks
- Enrich alerts for NOC/SOC workflows

---

BotNetProbe helps expose quiet threats hiding in noisy traffic. 🧠
