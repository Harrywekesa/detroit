# network_scanner.py

import socket
import nmap  # Make sure to install nmap with `pip install python-nmap`
import requests
import json
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(filename='vulnerability_report.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# NVD API Key (Replace with your actual NVD API key)
NVD_API_KEY = "8ac410a7-76f5-4068-9dca-ad8774880dac"  # Get your API key from https://nvd.nist.gov/developers

# Port Scanner Function
def port_scan(target_ip):
    """Scans open ports on a specified IP using nmap."""
    nm = nmap.PortScanner()
    nm.scan(target_ip, '1-1024')  # Scans ports from 1 to 1024
    open_ports = []

    for host in nm.all_hosts():
        print(f'Scanning {host} for open ports:')
        for port in nm[host]['tcp']:
            if nm[host]['tcp'][port]['state'] == 'open':
                open_ports.append(port)
                print(f'Port {port} is open')

    return open_ports


# OS Detection Function
def detect_os(target_ip):
    """Uses nmap to detect the operating system of the target server."""
    nm = nmap.PortScanner()
    try:
        nm.scan(target_ip, arguments='-O')
        os_data = nm[target_ip]['osmatch']
        if os_data:
            print(f'OS Detected: {os_data[0]["name"]}')
            return os_data[0]["name"]
    except Exception as e:
        print(f"Error detecting OS: {e}")
    return None


# Vulnerability Check with NVD API
import time

import os
import gzip
import json

def check_vulnerabilities(service_name, version):
    """Checks known vulnerabilities for a service by parsing local CVE JSON files."""
    cve_results = []
    data_folder = "cve_data"  # Folder where JSON files are stored

    try:
        for filename in os.listdir(data_folder):
            if filename.endswith(".json.gz"):
                # Open and parse the JSON file
                with gzip.open(os.path.join(data_folder, filename), 'rt', encoding='utf-8') as f:
                    data = json.load(f)
                    # Search for relevant CVEs
                    for item in data["CVE_Items"]:
                        description = item["cve"]["description"]["description_data"][0]["value"]
                        cve_id = item["cve"]["CVE_data_meta"]["ID"]
                        if service_name.lower() in description.lower() and version in description:
                            cve_results.append({
                                "cve_id": cve_id,
                                "description": description
                            })

    except Exception as e:
        print(f"Error checking vulnerabilities: {e}")

    return cve_results



# Scan Report
def generate_report(target_ip, open_ports, os_info, vulnerabilities):
    """Generates a report of the findings and logs it."""
    report = {
        "target_ip": target_ip,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "os_detected": os_info,
        "open_ports": open_ports,
        "vulnerabilities": vulnerabilities,
    }

    # Save report as JSON
    with open("scan_report.json", "w") as f:
        json.dump(report, f, indent=4)
    print("Report generated and saved to scan_report.json")

    # Log the report details
    logging.info("Scan report generated: %s", json.dumps(report, indent=4))


# Main function to initiate scanning
def main(target_ip):
    print(f"Initiating scan on {target_ip}...")
    
    # Step 1: Port Scan
    open_ports = port_scan(target_ip)

    # Step 2: OS Detection
    os_info = detect_os(target_ip)

    # Step 3: Vulnerability Check
    vulnerabilities = []
    for port in open_ports:
        # Placeholder services (these would normally be dynamically detected)
        service_name = "http" if port == 80 else "unknown"
        version = "1.0"  # Example version; normally this would be detected dynamically

        vuln_results = check_vulnerabilities(service_name, version)
        vulnerabilities.extend(vuln_results)

    # Step 4: Report Generation
    generate_report(target_ip, open_ports, os_info, vulnerabilities)


# Usage
if __name__ == "__main__":
    target_ip = input("Enter the target server IP address: ")
    main(target_ip)
