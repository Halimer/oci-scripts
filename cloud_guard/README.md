# Cloud Guard Scripts
This directory contains useful scripts for querying data from OCI CLoud Guard.

## All Detectors and Responders
The `all_detector_responders.py` script gets all the configuration and activity detectors rules and writes them to the `all_detectors.csv`.  It also gets all the responder rules and writes them to `all_responders.csv`

### Installaltion 
1. Download the python script:
```wget https://raw.githubusercontent.com/Halimer/oci_scripts/master/cloud_guard/all_detectors.py```
1. Create a virtual environment:
```python3 -m venv oci_scripts_venv```
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Install the dependences:
```pip3 install oci```

### Running the script on a local machine
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Run the script:
```python3 all_detector_responders.py```

### Running the script in Cloud Shell
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Run the script:
```python3 all_detector_responders.py -dt```