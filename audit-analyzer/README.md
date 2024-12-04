# OCI Audit Analyzer 
This directory contains useful script for querying OCI Audit data for a user's activity during a date range and outputs the activities into a CSV file. 


## Installaltion 
1. Download the python script:
```wget https://raw.githubusercontent.com/Halimer/oci-scripts/refs/heads/master/audit-analyzer/analyze-oci-audit.py```
1. Create a virtual environment:
```python3 -m venv oci_scripts_venv```
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Install the dependences:
```pip3 install oci```

## Usage Examples

### Running on Local Machine
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Run the script:
```python3 analyze-oci-audit.py --startdate 2024-12-02 --enddate 2024-12-03 --userid ocid1.user.oc1..```


### Running in Cloud Shell
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Run the script:
```python3 analyze-oci-audit.py -dt --startdate 2024-12-02 --enddate 2024-12-03 --userid ocid1.user.oc1..```

## Output
### CLI Output
```
Start time is: 2024-12-03T18:21:51Z
2024-12-02
2024-12-03
[{'start_date': datetime.date(2024, 12, 2), 'end_date': datetime.date(2024, 12, 3)}]
ocid1.user.oc1..
Processing Compartments...
Processed 70 Compartments
Processing Audit Logs...
         Found 1 audit events
         Found 6 audit events
         Found 1000 audit events
         Found 968 audit events
CSV: audit-log              --> <tenancy-name>_audit-log_2024_12_03_18_21.csv
Start Times: 2024-12-03T18:21:51Z
End Time is: 2024-12-03T18:22:53Z
Runtime was: 0:01:01.522111
```

### CSV File Fields
```
type,time,principalName,principalId,compartmentId,compartmentName,ipAddress,eventName,resourceId,userAgent,tenancy,extract_date
com.oraclecloud.virtualNetwork.GetVnic,2024-12-02 11:31:38.045000,<user-name> ,ocid1.user.oc1..,ocid1.compartment.oc1..,cra-db,10.0.0.1,GetVnic,ocid1.vnic.oc1.iad.,Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; ) Gecko/20100101 Firefox/132.0,ocid1.tenancy.oc1..,2024-12-03-15-58
com.oraclecloud.computeApi.ListVnicAttachments,2024-12-02 11:31:38.212000,<user-name> ,ocid1.user.oc1..,ocid1.compartment.oc1..,cra-db,10.0.0.1,ListVnicAttachments,,Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; ) Gecko/20100101 Firefox/132.0,ocid1.tenancy.oc1..,2024-12-03-15-58
com.oraclecloud.DatabaseService.GetDatabase,2024-12-02 11:31:28.344000,<user-name> ,ocid1.user.oc1..,ocid1.compartment.oc1..,cra,10.0.0.1,GetDatabase,ocid1.database.oc1.iad.,Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; ) Gecko/20100101 Firefox/132.0,ocid1.tenancy.oc1..,2024-12-03-15-58
com.oraclecloud.TelemetryPublicApi.ListAlarms,2024-12-02 11:31:28.589000,<user-name> ,ocid1.user.oc1..,ocid1.compartment.oc1..,cra,10.0.0.1,ListAlarms,,Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; ) Gecko/20100101 Firefox/132.0,ocid1.tenancy.oc1..,2024-12-03-15-58
```
