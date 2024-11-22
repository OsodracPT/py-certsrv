# py-certsrv

This is a simple litle Python script for the certsrv page (Microsoft AD Certificate Services), so that Python programs can get certificates without manual operation.

## Features

- **Key and CSR Generation**: Automatically generates RSA keys and CSRs using OpenSSL based on a configuration file.
- **Dynamic Certificate Template**: Allows the user to specify the certificate template dynamically.
- **Flexible File Naming**: Derives output file names (`key`, `csr`, and `crt`) based on the Common Name (CN) in the configuration file.
- **SAN Support**: Extracts Subject Alternative Names (SANs) from the configuration file for inclusion in the certificate request.
- **NTLM Authentication**: Uses NTLM for authentication with the AD CS server.
- **Automated Certificate Retrieval**: Downloads and saves the signed certificate automatically.

### Requirements 🧱

- Python 3.x
- Required Python modules: `requests`, `requests-ntlm` [requests-ntlm](https://pypi.org/project/requests-ntlm/)
- Filled request.cfg

### How to create the request.cfg file

Copy the request.cfg.example to request.cfg and fill it with the information from your organization.

### Notes

    Ensure the AD CS server URL is correct in the script.
    The requests.post call disables SSL verification (verify=False). Update this setting for production environments with a trusted certificate chain.
    Adjust the certificate template name to match your AD CS configuration.
    
### Example Usage

Prepare request.cfg with CN and [alt_names] sections.
Run the script:

```
./py-certsrv.py request.cfg
```

Enter the certificate template (optional).
