# Identity Domain App Analyzer
## Overview
This python scripts collects all apps in a identity domain and outputs a CSV and JSON (coming soon).

## Setup
1. Download identity_domain_app_analyzer.py: [https://raw.githubusercontent.com/Halimer/oci-scripts/refs/heads/identity-domain-oauth-collector/domain-analyzer/identity_domain_app_analyzer.py](https://raw.githubusercontent.com/Halimer/oci-scripts/refs/heads/identity-domain-oauth-collector/domain-analyzer/identity_domain_app_analyzer.py)
```
wget https://raw.githubusercontent.com/Halimer/oci-scripts/refs/heads/identity-domain-oauth-collector/domain-analyzer/identity_domain_app_analyzer.py
```
1. Create a Python Virtual Environment with required modules
```
python3 -m venv python-venv
source python-venv/bin/activate
pip3 install oci
pip3 install pytz
pip3 install requests
```

## Sample Usage
### Running on a Local Machine with config file that is a profile call my_profile
`python identity_domain_app_analyzer.py -t my_profile`

### Running on in Cloud Shell
`python identity_domain_app_analyzer.py -dt`


### Running on an OCI Instance with Instance Princple
`python identity_domain_app_analyzer.py -ip`



## Flags
```
usage: identity_domain_app_analyzer.py [-h] [-t CONFIG_PROFILE] [-ip] [-dt]

options:
  -h, --help         show this help message and exit
  -t CONFIG_PROFILE  Config file section to use (tenancy profile)
  -ip                Use Instance Principals for Authentication
  -dt                Use Delegation Token for Authentication
  ``` 