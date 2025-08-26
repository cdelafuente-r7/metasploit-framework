# MITRE ATT&CK Technique Categorization for Metasploit Modules

This directory contains scripts and data for categorizing Metasploit modules according to MITRE ATT&CK techniques.

## Files

### Input Files
- `mitre1.csv` - CSV file containing MITRE ATT&CK techniques with priority levels
  - Columns: Technique ID, Technique Name, MSF Tag Priority, Tactic, Description
  - Only techniques marked as "High" priority are processed

### Scripts
- `categorize_modules.py` - Initial categorization script with basic keyword matching
- `categorize_modules_refined.py` - **Recommended** - Refined script with weighted scoring
- `generate_summary.py` - Generates a summary report of categorization results

### Output Files
Generated files follow the naming pattern: `T{ID}-{technique_name}.txt`
- `T1003-os_credential_dumping_refined.txt` - OS Credential Dumping modules
- `T1021-remote_services_refined.txt` - Remote Services modules
- `T1055-process_injection_refined.txt` - Process Injection modules
- `T1059-command_and_scripting_interpreter_refined.txt` - Command/Script Interpreter modules
- `T1110-brute_force_refined.txt` - Brute Force modules
- `T1190-exploit_public-facing_application_refined.txt` - Public Application Exploit modules
- `T1210-exploitation_of_remote_services_refined.txt` - Remote Service Exploitation modules

## Usage

### Step 1: Ensure you have the MITRE techniques CSV
Make sure `mitre1.csv` exists with the required format. The provided sample includes 7 high-priority techniques.

### Step 2: Run the refined categorization script
```bash
python3 categorize_modules_refined.py
```

This will:
1. Read high priority techniques from `mitre1.csv`
2. Analyze all modules in the `modules/` directory
3. Check corresponding documentation in `documentation/modules/`
4. Generate categorization files for each technique

### Step 3: Generate summary report
```bash
python3 generate_summary.py
```

This provides an overview of results across all techniques.

## How the Analysis Works

The refined script uses a weighted scoring system:

### High Value Indicators (10 points in name/description, 3 points in content)
- Technique-specific phrases like "credential dump", "brute force", "process injection"
- Tool names like "mimikatz", "lsass", "ntds.dit"

### Medium Value Indicators (5 points in name/description)
- Related terms like "credential", "remote", "exploit"

### Path Indicators (2 points)
- Module path contains relevant keywords (e.g., "gather", "login", "brute")

### MITRE References (15 points)
- Module contains direct MITRE ATT&CK references

### Threshold
Modules with a score ≥ 5 are included in the categorization.

## Output Format

Each technique file contains:
- Header with technique details (ID, name, tactic, description)
- Count of related modules found
- For each module:
  - Module path relative to `modules/`
  - Documentation path (if available)
  - Analysis reasoning with score and matched indicators

## Notes

- Some modules may appear in multiple technique categories
- Documentation analysis is performed when `.md` files exist in `documentation/modules/`
- The script handles both Ruby (`.rb`) and Python (`.py`) modules
- Output files are excluded from git tracking via `.gitignore`

## Example Output

```
MITRE ATT&CK Technique: T1003 - OS Credential Dumping
Tactic: Credential Access
Description: Adversaries may attempt to dump credentials...

Total related modules found: 235

Module: post/windows/gather/hashdump.rb
Documentation: documentation/modules/post/windows/gather/hashdump.md
Analysis: Score: 20 - HIGH: 'password hash' in name/description; HIGH: 'hashdump' in content...
```

## Requirements

- Python 3.x
- Access to Metasploit framework repository structure
- CSV file with MITRE technique definitions