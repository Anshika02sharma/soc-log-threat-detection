import argparse
import re
import csv
import requests
from collections import defaultdict
import matplotlib.pyplot as plt

# -------------------------
# Command Line Arguments
# -------------------------

parser = argparse.ArgumentParser(description="SOC Log Analysis & Threat Detection Tool")

parser.add_argument("logfile", help="Path to log file")
parser.add_argument("--threshold", type=int, default=4,
                    help="Failed login threshold for brute force detection")

args = parser.parse_args()

log_file = args.logfile
THRESHOLD = args.threshold

# -------------------------
# Log Parsing
# -------------------------

failed_attempts = defaultdict(int)

pattern = r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"

with open(log_file, "r") as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            ip = match.group(1)
            failed_attempts[ip] += 1

print("\nFailed Login Attempts:\n")

for ip, count in failed_attempts.items():
    print(f"{ip} : {count} failed attempts")

# -------------------------
# Threat Detection
# -------------------------

print("\nThreat Detection:\n")

for ip, count in failed_attempts.items():
    if count >= THRESHOLD:
        print(f"[ALERT] Possible brute force attack from {ip} ({count} failed attempts)")

# -------------------------
# Attack Statistics
# -------------------------

print("\nAttack Statistics:\n")

total_attempts = sum(failed_attempts.values())
unique_ips = len(failed_attempts)

print(f"Total Failed Attempts: {total_attempts}")
print(f"Unique Attacking IPs: {unique_ips}")

top_ip = max(failed_attempts, key=failed_attempts.get)

print("\nTop Attacking IP:")
print(f"{top_ip} with {failed_attempts[top_ip]} failed attempts")

# -------------------------
# Security Report
# -------------------------

report_file = "security_report.txt"

with open(report_file, "w") as report:
    report.write("Security Threat Report\n\n")
    for ip, count in failed_attempts.items():
        report.write(f"{ip} : {count} failed login attempts\n")

print("\nSecurity report generated: security_report.txt")

# -------------------------
# IP Geolocation
# -------------------------

print("\nIP Geolocation:\n")

ip_locations = {}

for ip in failed_attempts.keys():
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()

        country = data.get("country", "Unknown")
        city = data.get("city", "Unknown")

        ip_locations[ip] = country

        print(f"{ip} → {city}, {country}")

    except:
        ip_locations[ip] = "Unknown"
        print(f"{ip} → Location lookup failed")

# -------------------------
# CSV Export
# -------------------------

with open("attack_report.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["IP Address", "Failed Attempts"])

    for ip, count in failed_attempts.items():
        writer.writerow([ip, count])

print("\nCSV report generated: attack_report.csv")

# -------------------------
# Threat Severity Levels
# -------------------------

print("\nThreat Severity Levels:\n")

for ip, count in failed_attempts.items():

    if count >= 5:
        severity = "HIGH"
    elif count >= 3:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    print(f"{ip} → {severity} threat ({count} failed attempts)")

# -------------------------
# Country-wise Attack Summary
# -------------------------

country_attacks = {}

print("\nCountry-wise Attack Summary:\n")

for country in ip_locations.values():
    country_attacks[country] = country_attacks.get(country, 0) + 1

for country, count in country_attacks.items():
    print(f"{country} → {count} attacking IP(s)")

# -------------------------
# Graph Visualization (LAST)
# -------------------------

ips = list(failed_attempts.keys())
attempts = list(failed_attempts.values())

plt.bar(ips, attempts)

plt.title("Failed Login Attempts by IP")
plt.xlabel("IP Address")
plt.ylabel("Failed Attempts")

plt.show()