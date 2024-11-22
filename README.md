# py-certsrv

This is a simple litle Python script for the certsrv page (Microsoft AD Certificate Services), so that Python programs can get certificates without manual operation.

### Requirements 🧱

- Python
- requests + [requests-ntlm](https://pypi.org/project/requests-ntlm/)
- Filled request.cfg
- Generated CSR file

### How to create the request.cfg file

Copy the request.cfg.example to request.cfg and fill it with the information from your organization.

### Manually Generate a Certificate Signing Request (CSR) Using OpenSSL

How to create the CHANGEME.domain.local.csr file

```
openssl req -new -newkey rsa:4096 -nodes -keyout CHANGEME.domain.local.key -out CHANGEME.domain.local.csr -config request.cfg -reqexts req_ext
```
