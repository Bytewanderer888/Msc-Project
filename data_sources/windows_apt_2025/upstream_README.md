# Windows-APT 2025 Dataset

## Overview
The *Windows-APT 2025* dataset provides a curated collection of host-level and network telemetry generated from controlled, repeatable simulations of Advanced Persistent Threat (APT)–inspired attack scenarios on Windows systems.  
All data were produced in a dedicated laboratory environment using Windows 10 hosts, the MITRE Caldera adversary emulation framework, Sysmon, and Wazuh.

The dataset is designed to support reproducible research in host-based intrusion detection, ATT&CK-mapped behavioral analysis, and evaluation of security analytics on Windows environments.

---

## Dataset Contents

### CSV Log Files
The dataset includes multiple CSV files capturing telemetry over different collection periods:

- **Per-period log files**  
  Examples:  
  `1-11-November.csv`, `12-13-December.csv`, `14-17-December.csv`, etc.  
  Each file contains host and network events collected during specific simulation windows.

- **Combined log file**  
  `combined.csv`  
  A consolidated file containing all per-period logs merged into a single dataset for convenience.

### Supplementary Metadata Files
- **`scenario_manifest.csv`**  
  Provides scenario-level metadata, including:
  - Scenario identifier and name  
  - Associated MITRE ATT&CK threat groups  
  - Simulated tactics and techniques  
  - Expected artifacts and reference links  

- **`validation_summary.csv`**  
  Summarizes execution and validation results for each scenario, including:
  - Number of runs  
  - Expected versus observed techniques  
  - Average success ratios  
  - Notes from manual validation and secondary review  

- **`checksums.sha256`**  
  SHA-256 checksums for data integrity verification.

---

## File Structure

```text
Windows-APT-2025/
├── *.csv                       # Per-period log files
├── combined.csv                # Merged log file
├── scenario_manifest.csv       # Scenario metadata and ATT&CK mappings
├── validation_summary.csv      # Scenario validation and reproducibility summary
├── checksums.sha256            # Integrity checksums
├── README.md                   # This file
└── scripts/
    ├── load_and_merge_logs.py
    └── parse_attack_mapping_and_filter.py
```

---

## Understanding the Log Fields
Each log entry contains rich telemetry collected from Sysmon and Wazuh.  
Key fields include (see Table 2 in the accompanying article for a complete description):

- **Timestamp** – Time when the event was recorded  
- **Agent Name** – Host or agent that generated the event  
- **Full-log** – Raw event content, including executed commands and parameters  
- **MITRE Tactic / Technique** – ATT&CK mappings associated with the event  
- **File Hashes (MD5, SHA256)** – Hashes of involved files when applicable  
- **Source and Destination IP/Port** – Network-related attributes  

---

## Loading and Merging the Logs

The following example demonstrates how to load and merge per-period CSV files using the provided helper script:

```bash
python scripts/load_and_merge_logs.py --data-dir . --out merged_logs.csv
```

This script:
- Automatically detects per-period CSV files  
- Excludes metadata files by default  
- Produces a unified CSV suitable for large-scale analysis  

---

## Using `scenario_manifest.csv`

The `scenario_manifest.csv` file enables ATT&CK-driven and scenario-level analysis.  
Typical use cases include:

- Filtering scenarios by MITRE ATT&CK tactics or techniques  
- Selecting scenarios associated with specific threat groups  
- Constructing targeted evaluation subsets for intrusion detection research  

Example:

```bash
python scripts/parse_attack_mapping_and_filter.py \
  --scenario-manifest scenario_manifest.csv \
  --technique T1059.003 \
  --out-scenarios filtered_scenarios.csv
```

---

## Using `validation_summary.csv`

The `validation_summary.csv` file supports reproducibility and quality assessment by:

- Summarizing execution consistency across repeated runs  
- Highlighting scenarios with stable and well-observed behavior  
- Comparing expected versus observed technique execution rates  

Researchers can use this file to prioritize scenarios for benchmarking or model evaluation.

---

## Example Analysis Workflow

A typical research workflow using this dataset may include:

1. Merging per-period logs into a single dataset  
2. Selecting scenarios of interest using `scenario_manifest.csv`  
3. Filtering or labeling logs based on ATT&CK tactics or techniques  
4. Training or evaluating intrusion detection and anomaly detection models  
5. Assessing reproducibility and stability using `validation_summary.csv`  

---

## Reproducibility Notes
All data were generated under controlled conditions using repeatable adversary emulation scenarios.  
While the dataset reflects realistic APT-inspired behavior on Windows systems, it represents simulated activity and does not capture the full diversity of real-world threat environments or advanced in-memory and kernel-level attacks.

---

## License
This dataset is released under the **Creative Commons Attribution 4.0 International (CC BY 4.0)** license.

---

## Citation
If you use this dataset, please cite:

> Mozaffari, M.; Yazdinejad, A.; Dehghantanha, A. (2025).  
> *Windows-APT 2025: A Dataset of Attack Scenarios Inspired by Advanced Persistent Threats on Windows Systems*.  
> Mendeley Data, V3, doi: 10.17632/b8fmtzvpy8.3

---

## Contact
For questions or issues related to the dataset, please refer to the associated Data in Brief article or contact the corresponding author.
