#!/usr/bin/env python3
"""
Generate a summary report of the MITRE technique categorization.
"""

import csv
import glob
import re

def generate_summary():
    print("MITRE ATT&CK Technique Categorization Summary")
    print("=" * 60)
    
    # Read CSV to get technique details
    techniques = {}
    with open('/home/runner/work/metasploit-framework/metasploit-framework/mitre1.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['MSF Tag Priority'].strip().lower() == 'high':
                techniques[row['Technique ID'].strip()] = {
                    'name': row['Technique Name'].strip(),
                    'tactic': row['Tactic'].strip(),
                    'description': row['Description'].strip()
                }
    
    print(f"\nAnalyzed {len(techniques)} high priority MITRE ATT&CK techniques:")
    for tid, details in techniques.items():
        print(f"  {tid}: {details['name']} ({details['tactic']})")
    
    print(f"\nResults Summary:")
    print("-" * 40)
    
    total_modules = 0
    
    # Process refined results
    for filename in sorted(glob.glob('/home/runner/work/metasploit-framework/metasploit-framework/T*_refined.txt')):
        with open(filename, 'r') as f:
            content = f.read()
            
        # Extract technique ID from filename
        technique_match = re.search(r'T(\d{4})', filename)
        if technique_match:
            tid = f"T{technique_match.group(1)}"
            
            # Count modules
            module_count = content.count('Module: ')
            total_modules += module_count
            
            # Get technique details
            tech_details = techniques.get(tid, {'name': 'Unknown', 'tactic': 'Unknown'})
            
            print(f"{tid} - {tech_details['name']}")
            print(f"  Tactic: {tech_details['tactic']}")
            print(f"  Related modules found: {module_count}")
            print(f"  Output file: {filename.split('/')[-1]}")
            print()
    
    print(f"Total modules categorized across all techniques: {total_modules}")
    print(f"\nNote: Some modules may be categorized under multiple techniques.")
    
    # Show top 5 modules for T1003 as example
    print("\nExample: Top 5 modules for T1003 (OS Credential Dumping):")
    print("-" * 50)
    
    with open('/home/runner/work/metasploit-framework/metasploit-framework/T1003-os_credential_dumping_refined.txt', 'r') as f:
        content = f.read()
        
    modules = re.findall(r'Module: ([^\n]+)\nDocumentation: ([^\n]+)\nAnalysis: ([^\n]+)', content)
    
    for i, (module, doc, analysis) in enumerate(modules[:5]):
        print(f"{i+1}. {module}")
        print(f"   Documentation: {doc}")
        print(f"   {analysis}")
        print()

if __name__ == "__main__":
    generate_summary()