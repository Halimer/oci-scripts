# Cloud Guard Scripts
This directory contains useful scripts for querying data from OCI CLoud Guard.

## All Detectors and Responders
The `get_cg_sz_data.py` script gets the following data from Cloud Guard and Security Zones.

- Cloud Guard Data (Flag: `-cg True`)
    - All Cloud Guard responders saved as `all_responders.csv`
    - All Cloud Guard detectors saved as `all_detectors.csv`
    - All Cloud Guard recommendations saved as `all_recommendations.csv`
    - All Cloud Guard problems saved as `all_problems.csv`
- Security Zones Data (Flag: `-sz True`)
    - Security Zones polices saved as security_zone_policies.csv

### Installaltion 
1. Download the python script:
```wget https://raw.githubusercontent.com/Halimer/oci-scripts/master/cloud_guard/get_cg_sz_data.py```
1. Create a virtual environment:
```python3 -m venv oci_scripts_venv```
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Install the dependences:
```pip3 install oci```

### Getting Security Zone data running the script on a local machine
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Run the script:
```python3 get_cg_sz_data.py -sz True```

### Getting Cloud Guard data running the script in Cloud Shell
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Run the script:
```python3 get_cg_sz_data.py -dt -cg True```

### Getting Cloud Guard and Security Zone data running the script on a local machine
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Run the script:
```python3 get_cg_sz_data.py -cg True -sz True```
