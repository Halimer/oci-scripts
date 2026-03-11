# Cloud Guard Scripts
This directory contains scripts for querying OCI Cloud Guard and Security Zones data.

## Script
`get_cg_sz_data.py` supports two top-level workflows:
1. `export` for bulk Cloud Guard / Security Zones exports
2. `problem` for enriched problem details (problem, sightings, impacted resources, endpoints)

If no arguments are provided, the script prints the help menu.

## Installation
1. Download the script:
```bash
wget https://raw.githubusercontent.com/Halimer/oci-scripts/master/cloud_guard/get_cg_sz_data.py
```
2. Create a virtual environment:
```bash
python3 -m venv oci_scripts_venv
```
3. Source the environment:
```bash
source oci_scripts_venv/bin/activate
```
4. Install dependencies:
```bash
pip3 install oci
```

## Usage
```bash
python3 get_cg_sz_data.py [-t PROFILE] [-p PROXY] [-ip] [-dt] [--region REGION] {export,problem} ...
```

### Global flags
- `-t`, `--profile`: OCI config profile name
- `-p`, `--proxy`: HTTPS proxy (example: `proxy.example.com:80`)
- `-ip`: Use instance principals auth
- `-dt`: Use delegation token auth
- `--region`: Override region in loaded config

## Commands
### `export`
Exports Cloud Guard and/or Security Zones datasets.

```bash
python3 get_cg_sz_data.py export {cloud-guard|security-zones|all} [--output {json,csv}] [--output-file FILE] [--pretty]
```

- Default output format is `csv`
- CSV mode writes the legacy files in current directory:
  - `all_responders.csv`
  - `all_detectors.csv`
  - `all_problems.csv`
  - `all_recommendations.csv`
  - `security_zone_policies.csv`
- JSON mode returns a consolidated payload to stdout or `--output-file`

### `problem get`
Gets one enriched problem record by OCID, including:
- `sightings`
- `impacted_resources` per sighting
- `endpoints` per sighting

```bash
python3 get_cg_sz_data.py problem get --problem-ocid OCID [--output {json,csv}] [--output-file FILE] [--pretty]
```

- Default output format is `json`
- CSV mode writes a summary row for the problem record

### `problem list`
Gets enriched details for all problems (optionally filtered).

```bash
python3 get_cg_sz_data.py problem list [--detector-name NAME] [--output {json,csv}] [--output-file FILE] [--pretty]
```

- `--detector-name` is case-insensitive exact match (no substring matching)
- Default output format is `json`
- CSV mode writes summary rows for matched problems

## Examples
### Help
```bash
python3 get_cg_sz_data.py
python3 get_cg_sz_data.py --help
python3 get_cg_sz_data.py export --help
python3 get_cg_sz_data.py problem --help
```

### Authentication flags
Use local config (default):
```bash
python3 get_cg_sz_data.py export all
```

Use instance principals:
```bash
python3 get_cg_sz_data.py -ip export cloud-guard
```

Use delegation token:
```bash
python3 get_cg_sz_data.py -dt export cloud-guard
```

Use non-default profile:
```bash
python3 get_cg_sz_data.py -t MYPROFILE export cloud-guard
```

Use proxy:
```bash
python3 get_cg_sz_data.py -p proxy.example.com:80 export all
```

Use region override:
```bash
python3 get_cg_sz_data.py --region us-ashburn-1 export all
```

### Export command examples
Cloud Guard CSV exports:
```bash
python3 get_cg_sz_data.py export cloud-guard
```

Security Zones CSV export:
```bash
python3 get_cg_sz_data.py export security-zones
```

All CSV exports:
```bash
python3 get_cg_sz_data.py export all
```

Cloud Guard JSON to stdout:
```bash
python3 get_cg_sz_data.py export cloud-guard --output json --pretty
```

All JSON to file:
```bash
python3 get_cg_sz_data.py export all --output json --output-file export_all.json --pretty
```

### Problem command examples
Get one problem (JSON stdout):
```bash
python3 get_cg_sz_data.py problem get --problem-ocid ocid1.cloudguardproblem.oc1..<unique_id>
```

Get one problem and write JSON to file:
```bash
python3 get_cg_sz_data.py problem get --problem-ocid ocid1.cloudguardproblem.oc1..<unique_id> --output-file problem_details.json --pretty
```

Get one problem as CSV summary:
```bash
python3 get_cg_sz_data.py problem get --problem-ocid ocid1.cloudguardproblem.oc1..<unique_id> --output csv --output-file problem_summary.csv
```

List all problems with details (JSON):
```bash
python3 get_cg_sz_data.py problem list --pretty
```

List all problems filtered by detector/problem name:
```bash
python3 get_cg_sz_data.py problem list --detector-name ROGUE_USER --output-file rogue_user_problems.json --pretty
```

List all problems as CSV summary:
```bash
python3 get_cg_sz_data.py problem list --output csv --output-file problems_summary.csv
```
