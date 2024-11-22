#!/usr/bin/python3
#
# Signs SSL certificates automatically by Microsoft AD Certificate Services
# Expects the path of the request.cfg file as the first argument and the path for the output CSR as the second argument.
#
import requests
from requests_ntlm import HttpNtlmAuth
import getpass
import re
import urllib3
import sys
import subprocess
import os

# Suppress only the specific InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Prompt for server details and credentials
server_url = "https://your-ad-server/certsrv/certfnsh.asp"
username = input("Enter your username: ")
password = getpass.getpass("Enter your password: ")

# Get the request file path and CSR path from arguments
if len(sys.argv) < 2:
    print("Usage: script.py <request.cfg path>")
    sys.exit(1)

request_file_path = sys.argv[1]

# Prompt for the certificate template (with a default value)
cert_template = input("Enter the certificate template (default: WebServer2): ") or "WebServer2"

# Derive file names dynamically based on the Common Name (CN) in request.cfg
try:
    with open(request_file_path, "r") as req_file:
        req_data = req_file.read()
    cn_match = re.search(r"CN\s*=\s*(.+)", req_data)
    if not cn_match:
        print("ERROR: Could not find 'CN' in the request.cfg file.")
        sys.exit(1)
    common_name = cn_match.group(1).strip()
except FileNotFoundError:
    print(f"ERROR: Request file not found at {request_file_path}")
    sys.exit(1)

key_file_path = f"{common_name}.key"
csr_file_path = f"{common_name}.csr"

# Generate key and CSR
print(f"Generating key: {key_file_path} and CSR: {csr_file_path}...")

try:
    subprocess.run([
        "openssl", "req", "-new", "-newkey", "rsa:4096", "-nodes",
        "-keyout", key_file_path,
        "-out", csr_file_path,
        "-config", request_file_path,
        "-reqexts", "req_ext"
    ], check=True)
    print("Key and CSR generated successfully.")
except subprocess.CalledProcessError as e:
    print(f"ERROR: Failed to generate key and CSR: {e}")
    sys.exit(1)

# Read CSR file contents
try:
    with open(csr_file_path, 'r') as csr_file:
        csr_data = csr_file.read()
except FileNotFoundError:
    print(f"ERROR: CSR file not found at {csr_file_path}")
    sys.exit(1)

# Initialize the dns_names list
dns_names = []

# Extract DNS entries from the [alt_names] section
in_alt_names_section = False
for line in req_data.splitlines():
    line = line.strip()
    
    if line.startswith("[alt_names]"):
        in_alt_names_section = True
        continue  # Skip the section header

    if in_alt_names_section:
        if line.startswith("DNS."):
            match = re.match(r'DNS\.\d+\s*=\s*(.*)', line)
            if match:
                dns_names.append(match.group(1).strip())

if not dns_names:
    print("ERROR: No DNS names found in the [alt_names] section.")
    sys.exit(1)

print("Extracted DNS Names:", dns_names)

# Construct SAN attribute string
san_attributes = "&".join([f"dns={dns}" for dns in dns_names])

# Form data for the certificate request
data = {
    "Mode": "newreq",
    "CertRequest": csr_data,
    "CertAttrib": f"CertificateTemplate:{cert_template}\nSAN:{san_attributes}",
    "FriendlyType": "Saved-Request",
    "TargetStoreFlags": "0",
    "SaveCert": "yes"
}

# Submit request to AD CS server with NTLM authentication
try:
    response = requests.post(
        server_url,
        data=data,
        auth=HttpNtlmAuth(username, password),
        verify=False
    )

    if response.status_code == 200:
        match = re.search(r'certnew.cer\?ReqID=(\d+)&', response.text)
        if match:
            request_id = match.group(1)
            print(f"Certificate request submitted successfully. Request ID: {request_id}")
            
            base_url = server_url.rsplit('/', 1)[0]
            download_url = f"{base_url}/certnew.cer?ReqID={request_id}&Enc=b64"
            cert_response = requests.get(download_url, auth=HttpNtlmAuth(username, password), verify=False)
            
            if cert_response.status_code == 200:
                cert_file_path = f"{common_name}.crt"
                with open(cert_file_path, 'wb') as cert_file:
                    cert_file.write(cert_response.content)
                print(f"Certificate downloaded and saved as {cert_file_path}")
            else:
                print(f"ERROR: Failed to download certificate. Status code: {cert_response.status_code}")
        else:
            print("ERROR: Could not retrieve Request ID from response.")
    else:
        print(f"ERROR: Failed to submit request. Status code: {response.status_code}")
        print(response.text)
except requests.exceptions.RequestException as e:
    print(f"ERROR: An error occurred during the request: {e}")
