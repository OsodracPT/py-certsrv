#!/usr/bin/python3
#
# Signs SSL certificates automatically by Microsoft AD Certificate Services
# Expects the path of the request.cfg file as the first argument and the path for the csr as the second argument.
#
# 
import requests
from requests_ntlm import HttpNtlmAuth
import getpass
import re
import urllib3
import sys

# Suppress only the specific InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Prompt for server details and credentials
# CERTSRV_URL = input("Enter the AD CS URL (e.g., http://your-ad-server/certsrv/certfnsh.asp): ")
server_url = "https://your-ad-server/certsrv/certfnsh.asp"
username = input("Enter your username: ")
password = getpass.getpass("Enter your password: ")
#CSR_PATH = input("Enter the full path to your CSR file (e.g., /path/to/your/request.csr): ")
csr_file_path = sys.argv[2]
# Get the request file path from the first argument
request_file_path = sys.argv[1]

# Read CSR file contents
try:
    with open(csr_file_path, 'r') as csr_file:
        csr_data = csr_file.read()
except FileNotFoundError:
    print(f"ERROR: CSR file not found at {csr_file_path}")
    exit(1)


# Initialize the dns_names list
dns_names = []

# Read the request file and extract DNS entries
with open(request_file_path, "r") as req_file:
    lines = req_file.readlines()
    in_alt_names_section = False

    for line in lines:
        line = line.strip()
        
        if line.startswith("[alt_names]"):
            in_alt_names_section = True
            continue  # Skip the section header

        if in_alt_names_section:
            if line.startswith("DNS."):
                # Extract the DNS entry
                match = re.match(r'DNS\.\d+\s*=\s*(.*)', line)
                if match:
                    dns_names.append(match.group(1).strip())

# Print extracted DNS names
print("Extracted DNS Names:", dns_names)

# Construct SAN attribute string
san_attributes = "&".join([f"dns={dns}" for dns in dns_names])

# Form data for the certificate request
data = {
    "Mode": "newreq",                           # Specifies that it's a new request
    "CertRequest": csr_data,                    # CSR data
    "CertAttrib": f"CertificateTemplate:WebServer2\nSAN:{san_attributes}",  # Adjust the template if necessary
    "FriendlyType": "Saved-Request",            # Friendly name (optional)
    "TargetStoreFlags": "0",                    # Store location flags
    "SaveCert": "yes"                           # Save the certificate
}

# Submit request to AD CS server with NTLM authentication
try:
    response = requests.post(
        server_url,
        data=data,
        #HttpNtlmAuth(f"{DOMAIN}\\{USERNAME}", PASSWORD)
        auth=HttpNtlmAuth(username, password),
        verify=False  # Disable SSL verification if the server has a self-signed cert; not recommended for production
    )
 # Check response status
    if response.status_code == 200:
# Extract the Request ID from the response
        match = re.search(r'certnew.cer\?ReqID=(\d+)&', response.text)
        if match:
            request_id = match.group(1)
            print(f"Certificate request submitted successfully. Request ID: {request_id}")
            
            # Download the certificate in Base64 format
            # Strip any trailing segments (like certfnsh.asp) from server_url if present
            base_url = server_url.rsplit('/', 1)[0]  # Removes only the last segment (/certfnsh.asp)

            # Correct download URL with base URL
            download_url = f"{base_url}/certnew.cer?ReqID={request_id}&Enc=b64"
            cert_response = requests.get(download_url, auth=HttpNtlmAuth(username, password), verify=False)
            
            if cert_response.status_code == 200:
                # Save the certificate to a .crt file
                cert_file_path = f"{csr_file_path.rsplit('.', 1)[0]}.crt"
                #print(cert_file_path)
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
