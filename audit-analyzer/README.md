# OCI Audit Analyzer 
This directory contains a useful script for querying OCI Audit data for a user's activity over a date range and exporting the results to a CSV file.

This script may take some time to run, especially across larger date ranges or tenancies with more audit activity. For best results, run it from a local machine instead of Cloud Shell.


## Installation
1. Download the Python script:
```wget https://raw.githubusercontent.com/Halimer/oci-scripts/refs/heads/master/audit-analyzer/analyze-oci-audit.py```
1. Create a virtual environment:
```python3 -m venv oci_scripts_venv```
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Install the dependencies:
```pip3 install oci```


## Help Documentation
```
usage: analyze-oci-audit.py [-h] [-t CONFIG_PROFILE] [-i FILE_NAME] --startdate STARTDATE --enddate ENDDATE [--allfields] [--userid USERID] [-ip] [-dt]

options:
  -h, --help            show this help message and exit
  -t CONFIG_PROFILE     Config file section to use (tenancy profile)
  -i FILE_NAME          Currently not used
  --startdate STARTDATE
                        Start Date example: 2024-09-01
  --enddate ENDDATE     End Date example: 2024-10-10
  --allfields           Retrieves all fields in the audit record; works only without --userid
  --userid USERID       User OCID example: ocid1.user.oc1..
  -ip                   Use Instance Principals for Authentication
  -dt                   Use Delegation Token for Authentication
  ```

## Usage Examples


### Running in Cloud Shell (recommended only for targeted user queries)
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Run the script for a single user's log records:
```python3 analyze-oci-audit.py -dt --startdate 2024-12-02 --enddate 2024-12-03 --userid ocid1.user.oc1..```


### Running on an OCI Server with Instance Principals
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Run the script for a single user's log records:
```python3 analyze-oci-audit.py -ip --startdate 2024-12-02 --enddate 2024-12-03 --userid ocid1.user.oc1..```
1. Run the script for all log records:
```python3 analyze-oci-audit.py -ip --startdate 2024-12-02 --enddate 2024-12-03```
1. Run a full-tenancy export that includes all available audit fields:
```python3 analyze-oci-audit.py -ip --allfields --startdate 2024-12-02 --enddate 2024-12-03```

`--allfields` is intended for full-tenancy exports and cannot be used with `--userid`. It queries audit records one day at a time and may take significantly longer than the standard all-records export, especially for larger date ranges or busy tenancies.

### Running on Local Machine
1. Source the environment:
```source oci_scripts_venv/bin/activate```
1. Run the script for a single user's log records:
```python3 analyze-oci-audit.py --startdate 2024-12-02 --enddate 2024-12-03 --userid ocid1.user.oc1..```
1. Run the script for all log records:
```python3 analyze-oci-audit.py --startdate 2024-12-02 --enddate 2024-12-03```
1. Run a full-tenancy export that includes all available audit fields:
```python3 analyze-oci-audit.py --allfields --startdate 2024-12-02 --enddate 2024-12-03```

`--allfields` is intended for full-tenancy exports and cannot be used with `--userid`. It queries audit records one day at a time and may take significantly longer than the standard all-records export, especially for larger date ranges or busy tenancies.

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

### Sample File Fields

#### Regular Run

The regular-run sample (`<tenancy-name>-audit-2026-07-03-to-2026-07-03-ext-2026_07_16_13_54.json`) contains these fields:

```
type
data.identity.principalId
data.compartmentId
data.compartmentName
data.identity.ipAddress
data.identity.principalName
data.eventName
data.resourceId
data.identity.userAgent
datetime
id
data.identity.credentials
```

#### `--allfields` Run

The `--allfields` sample (`<tenancy-name>-audit-2026-07-03-to-2026-07-03-ext-2026_07_16_13_57.json`) contains these top-level fields:

```
datetime
logContent
```

`logContent` contains the full nested OCI Audit event. The following are all 162 populated nested leaf fields present in the sample. `[]` identifies an array-valued field; fields vary by event type.

```
logContent.data.additionalDetails
logContent.data.additionalDetails.X-Real-Port
logContent.data.additionalDetails.bucketName
logContent.data.additionalDetails.digest
logContent.data.additionalDetails.namespace
logContent.data.additionalDetails.path
logContent.data.availabilityDomain
logContent.data.compartmentId
logContent.data.compartmentName
logContent.data.definedTags
logContent.data.definedTags.Oracle-Tags.CreatedBy
logContent.data.definedTags.Oracle-Tags.CreatedOn
logContent.data.definedTags.cis.CreatedBy
logContent.data.definedTags.cis.CreatedOn
logContent.data.eventGroupingId
logContent.data.eventName
logContent.data.freeformTags
logContent.data.freeformTags.VCN
logContent.data.identity.authType
logContent.data.identity.callerId
logContent.data.identity.callerName
logContent.data.identity.consoleSessionId
logContent.data.identity.credentials
logContent.data.identity.ipAddress
logContent.data.identity.principalId
logContent.data.identity.principalName
logContent.data.identity.tenantId
logContent.data.identity.userAgent
logContent.data.message
logContent.data.request.action
logContent.data.request.headers.Accept-Encoding[]
logContent.data.request.headers.Accept[]
logContent.data.request.headers.Authorization[]
logContent.data.request.headers.Connection[]
logContent.data.request.headers.Content-Length[]
logContent.data.request.headers.Content-Type[]
logContent.data.request.headers.Date[]
logContent.data.request.headers.Host-Identifier[]
logContent.data.request.headers.Is-Config-Valid[]
logContent.data.request.headers.Opc-Client-Info[]
logContent.data.request.headers.Opc-Client-Retries[]
logContent.data.request.headers.Opc-Request-Id[]
logContent.data.request.headers.User-Agent[]
logContent.data.request.headers.X-Forwarded-For[]
logContent.data.request.headers.X-Forwarded-Host[]
logContent.data.request.headers.X-OCI-LB-NetworkMetadata[]
logContent.data.request.headers.X-OCI-LB-PrivateAccessMetadata[]
logContent.data.request.headers.X-Oracle-Auth-Client-CN[]
logContent.data.request.headers.X-Real-IP[]
logContent.data.request.headers.X-Real-Port[]
logContent.data.request.headers.authorization[]
logContent.data.request.headers.date[]
logContent.data.request.headers.host[]
logContent.data.request.headers.oci-original-host[]
logContent.data.request.headers.oci-original-url[]
logContent.data.request.headers.oci-splat-service-operation-id[]
logContent.data.request.headers.opc-client-info[]
logContent.data.request.headers.opc-client-retries[]
logContent.data.request.headers.opc-idempotency-token[]
logContent.data.request.headers.opc-obo-token[]
logContent.data.request.headers.opc-principal[]
logContent.data.request.headers.opc-request-id[]
logContent.data.request.headers.x-content-sha256[]
logContent.data.request.id
logContent.data.request.parameters.accessLevel[]
logContent.data.request.parameters.availabilityDomain[]
logContent.data.request.parameters.compartmentIdInSubtree[]
logContent.data.request.parameters.compartmentId[]
logContent.data.request.parameters.configurationType[]
logContent.data.request.parameters.dryRun[]
logContent.data.request.parameters.fields[]
logContent.data.request.parameters.fluentType[]
logContent.data.request.parameters.fluentVersion[]
logContent.data.request.parameters.lifecycleState[]
logContent.data.request.parameters.limit[]
logContent.data.request.parameters.operatingSystemType[]
logContent.data.request.parameters.page[]
logContent.data.request.parameters.param0[]
logContent.data.request.parameters.param1[]
logContent.data.request.parameters.sortBy[]
logContent.data.request.parameters.sortOrder[]
logContent.data.request.parameters.vcnId[]
logContent.data.request.path
logContent.data.resourceId
logContent.data.response.headers.Access-Control-Expose-Headers[]
logContent.data.response.headers.Cache-Control[]
logContent.data.response.headers.Connection[]
logContent.data.response.headers.Content-Encoding[]
logContent.data.response.headers.Content-Length[]
logContent.data.response.headers.Content-Type[]
logContent.data.response.headers.Date[]
logContent.data.response.headers.ETag[]
logContent.data.response.headers.Pragma[]
logContent.data.response.headers.Strict-Transport-Security[]
logContent.data.response.headers.Transfer-Encoding[]
logContent.data.response.headers.Vary[]
logContent.data.response.headers.X-Content-Type-Options[]
logContent.data.response.headers.access-control-allow-credentials[]
logContent.data.response.headers.access-control-allow-methods[]
logContent.data.response.headers.access-control-allow-origin[]
logContent.data.response.headers.access-control-expose-headers[]
logContent.data.response.headers.cache-control[]
logContent.data.response.headers.connection[]
logContent.data.response.headers.date[]
logContent.data.response.headers.etag[]
logContent.data.response.headers.oci-splat-authorization-verify-content[]
logContent.data.response.headers.opc-limit[]
logContent.data.response.headers.opc-next-page[]
logContent.data.response.headers.opc-request-id[]
logContent.data.response.headers.strict-transport-security[]
logContent.data.response.headers.x-api-id[]
logContent.data.response.headers.x-content-type-options[]
logContent.data.response.message
logContent.data.response.payload
logContent.data.response.payload.Id
logContent.data.response.payload.ResourceName
logContent.data.response.payload.id
logContent.data.response.payload.resourceName
logContent.data.response.responseTime
logContent.data.response.status
logContent.data.stateChange
logContent.data.stateChange.current
logContent.data.stateChange.current.Current state.compartmentId
logContent.data.stateChange.current.Current state.definedTags.Oracle-Tags.CreatedBy
logContent.data.stateChange.current.Current state.definedTags.Oracle-Tags.CreatedOn
logContent.data.stateChange.current.Current state.definedTags.cis.CreatedBy
logContent.data.stateChange.current.Current state.definedTags.cis.CreatedOn
logContent.data.stateChange.current.Current state.displayName
logContent.data.stateChange.current.Current state.floatingPrivateIPs[]
logContent.data.stateChange.current.Current state.hasFloatingIP
logContent.data.stateChange.current.Current state.id
logContent.data.stateChange.current.Current state.internalAvailabilityDomain
logContent.data.stateChange.current.Current state.isBMVnic
logContent.data.stateChange.current.Current state.isBridgeVnic
logContent.data.stateChange.current.Current state.isEdpEnabled
logContent.data.stateChange.current.Current state.isMacLearningEnabled
logContent.data.stateChange.current.Current state.isManaged
logContent.data.stateChange.current.Current state.isNatIpAllocationDisabled
logContent.data.stateChange.current.Current state.isPrimaryVnic
logContent.data.stateChange.current.Current state.isPrivateIpCreationBlocked
logContent.data.stateChange.current.Current state.nsgIds[]
logContent.data.stateChange.current.Current state.overlayIp
logContent.data.stateChange.current.Current state.overlayMac
logContent.data.stateChange.current.Current state.ownerId
logContent.data.stateChange.current.Current state.skipSourceDestCheck
logContent.data.stateChange.current.Current state.state
logContent.data.stateChange.current.Current state.subnetCidr
logContent.data.stateChange.current.Current state.subnetId
logContent.data.stateChange.current.Current state.symmetricHashingEnabled
logContent.data.stateChange.current.Current state.timeCreated
logContent.data.stateChange.current.Current state.virtualRouterIp
logContent.data.stateChange.previous
logContent.dataschema
logContent.id
logContent.oracle.compartmentid
logContent.oracle.ingestedtime
logContent.oracle.loggroupid
logContent.oracle.tenantid
logContent.source
logContent.specversion
logContent.time
logContent.type
```
