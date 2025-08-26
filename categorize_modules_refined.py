#!/usr/bin/env python3
"""
Refined script to categorize Metasploit modules by MITRE ATT&CK techniques.
Uses more precise analysis with weighted keywords and context.
"""

import csv
import os
import re
import glob
from pathlib import Path

class RefinedModuleCategorizer:
    def __init__(self, repo_path, csv_path):
        self.repo_path = Path(repo_path)
        self.csv_path = csv_path
        self.modules_path = self.repo_path / "modules"
        self.docs_path = self.repo_path / "documentation" / "modules"
        
    def read_mitre_csv(self):
        """Read the MITRE CSV file and return high priority techniques."""
        high_priority_techniques = []
        
        with open(self.csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['MSF Tag Priority'].strip().lower() == 'high':
                    high_priority_techniques.append({
                        'id': row['Technique ID'].strip(),
                        'name': row['Technique Name'].strip(),
                        'description': row['Description'].strip(),
                        'tactic': row['Tactic'].strip()
                    })
        
        return high_priority_techniques
    
    def get_all_modules(self):
        """Get all module files in the repository."""
        module_files = []
        for ext in ['rb', 'py']:
            pattern = str(self.modules_path / f"**/*.{ext}")
            module_files.extend(glob.glob(pattern, recursive=True))
        return module_files
    
    def get_module_documentation_path(self, module_path):
        """Get the corresponding documentation path for a module."""
        rel_path = Path(module_path).relative_to(self.modules_path)
        
        # Convert plural directory names to singular for documentation
        parts = list(rel_path.parts)
        if len(parts) > 0:
            # Handle the type conversion (e.g., exploits -> exploit)
            if parts[0].endswith('s') and parts[0] != 'post':
                parts[0] = parts[0][:-1]  # Remove trailing 's'
        
        # Change extension to .md
        if parts[-1].endswith('.rb') or parts[-1].endswith('.py'):
            parts[-1] = parts[-1].rsplit('.', 1)[0] + '.md'
        
        doc_path = self.docs_path / Path(*parts)
        return doc_path if doc_path.exists() else None
    
    def read_module_file(self, module_path):
        """Read and parse a module file to extract key information."""
        try:
            with open(module_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract description from update_info method
            description = ""
            info_match = re.search(r"update_info\s*\(\s*info,\s*{([^}]+)}", content, re.DOTALL)
            if info_match:
                info_content = info_match.group(1)
                desc_match = re.search(r"'Description'\s*=>\s*%q\{([^}]+)\}", info_content, re.DOTALL)
                if desc_match:
                    description = desc_match.group(1).strip()
            
            # Extract Name field
            name = ""
            name_match = re.search(r"'Name'\s*=>\s*['\"]([^'\"]+)['\"]", content)
            if name_match:
                name = name_match.group(1).strip()
            
            # Extract References
            references = []
            ref_matches = re.findall(r"'URL',\s*['\"]([^'\"]+)['\"]", content)
            references.extend(ref_matches)
            
            return {
                'name': name,
                'description': description,
                'references': references,
                'content': content
            }
        except Exception as e:
            print(f"Error reading {module_path}: {e}")
            return None
    
    def read_documentation_file(self, doc_path):
        """Read module documentation file."""
        try:
            with open(doc_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return content
        except Exception as e:
            return None
    
    def analyze_module_for_technique(self, module_path, technique):
        """Analyze if a module relates to a specific MITRE technique with refined scoring."""
        module_info = self.read_module_file(module_path)
        if not module_info:
            return False, "Could not read module file"
        
        doc_path = self.get_module_documentation_path(module_path)
        doc_content = ""
        if doc_path:
            doc_content = self.read_documentation_file(doc_path) or ""
        
        technique_id = technique['id']
        
        # Create analysis text (prioritize name and description)
        name_desc = (module_info['name'] + " " + module_info['description']).lower()
        full_content = (module_info['content'] + " " + doc_content).lower()
        
        score = 0
        matched_indicators = []
        
        # Define highly specific indicators for each technique
        technique_indicators = {
            'T1003': {
                'high_value': ['credential dump', 'hash dump', 'lsass', 'sam dump', 'ntds.dit', 
                              'mimikatz', 'hashdump', 'cachedump', 'lsa secrets', 'password hash'],
                'medium_value': ['credential', 'password extract', 'hash extract', 'secrets'],
                'low_value': ['dump', 'hash', 'password'],
                'path_indicators': ['gather', 'hashdump', 'cachedump', 'lsa', 'sam']
            },
            'T1021': {
                'high_value': ['remote login', 'ssh login', 'rdp login', 'smb login', 'winrm login',
                              'telnet login', 'vnc login', 'remote service', 'lateral movement'],
                'medium_value': ['ssh', 'rdp', 'smb', 'winrm', 'telnet', 'vnc', 'remote'],
                'low_value': ['login', 'connect', 'service'],
                'path_indicators': ['ssh', 'rdp', 'smb', 'winrm', 'telnet', 'vnc', 'login']
            },
            'T1055': {
                'high_value': ['process injection', 'dll injection', 'shellcode injection', 
                              'code injection', 'memory injection', 'process hollowing'],
                'medium_value': ['inject', 'dll', 'shellcode', 'memory'],
                'low_value': ['process', 'memory'],
                'path_indicators': ['inject', 'dll', 'memory', 'process']
            },
            'T1059': {
                'high_value': ['command execution', 'script execution', 'shell execution',
                              'powershell', 'cmd execution', 'bash execution'],
                'medium_value': ['command', 'script', 'shell', 'execute', 'run'],
                'low_value': ['cmd', 'bash', 'powershell'],
                'path_indicators': ['cmd', 'shell', 'exec', 'script', 'powershell']
            },
            'T1110': {
                'high_value': ['brute force', 'password brute', 'login brute', 'dictionary attack',
                              'password crack', 'credential brute'],
                'medium_value': ['brute', 'crack', 'dictionary', 'wordlist'],
                'low_value': ['login', 'password', 'force'],
                'path_indicators': ['brute', 'login', 'crack', 'dict']
            },
            'T1190': {
                'high_value': ['web exploit', 'web vulnerability', 'cve-', 'remote exploit',
                              'public application', 'http exploit'],
                'medium_value': ['exploit', 'vulnerability', 'cve', 'web'],
                'low_value': ['http', 'web', 'remote'],
                'path_indicators': ['http', 'web', 'exploit', 'cve']
            },
            'T1210': {
                'high_value': ['remote service exploit', 'service exploitation', 'lateral movement',
                              'remote vulnerability', 'service attack'],
                'medium_value': ['remote', 'service', 'exploit', 'lateral'],
                'low_value': ['service', 'remote'],
                'path_indicators': ['service', 'remote', 'lateral', 'exploit']
            }
        }
        
        indicators = technique_indicators.get(technique_id, {})
        
        # Score high-value indicators in name/description (highest weight)
        for indicator in indicators.get('high_value', []):
            if indicator in name_desc:
                score += 10
                matched_indicators.append(f"HIGH: '{indicator}' in name/description")
        
        # Score medium-value indicators in name/description
        for indicator in indicators.get('medium_value', []):
            if indicator in name_desc:
                score += 5
                matched_indicators.append(f"MED: '{indicator}' in name/description")
        
        # Score high-value indicators in full content (lower weight)
        for indicator in indicators.get('high_value', []):
            if indicator in full_content:
                score += 3
                matched_indicators.append(f"HIGH: '{indicator}' in content")
        
        # Score path indicators (module path suggests relevance)
        module_path_lower = str(module_path).lower()
        for indicator in indicators.get('path_indicators', []):
            if indicator in module_path_lower:
                score += 2
                matched_indicators.append(f"PATH: '{indicator}' in module path")
        
        # Check for MITRE references in the module
        for ref in module_info['references']:
            if technique_id.lower() in ref.lower() or 'mitre.org' in ref.lower():
                score += 15
                matched_indicators.append(f"MITRE: MITRE reference found: {ref}")
        
        # Set threshold for inclusion (more restrictive)
        is_related = score >= 5
        
        reasoning = f"Score: {score} - " + "; ".join(matched_indicators[:5])  # Show top 5 matches
        if doc_path:
            reasoning += f" (analyzed module source and documentation)"
        else:
            reasoning += " (analyzed module source only)"
        
        return is_related, reasoning
    
    def categorize_modules(self):
        """Main method to categorize all modules by high priority techniques."""
        print("Reading MITRE techniques from CSV...")
        techniques = self.read_mitre_csv()
        
        print(f"Found {len(techniques)} high priority techniques:")
        for tech in techniques:
            print(f"  {tech['id']}: {tech['name']}")
        
        print("\nGetting all modules...")
        all_modules = self.get_all_modules()
        print(f"Found {len(all_modules)} modules to analyze")
        
        # Process each technique
        for technique in techniques:
            technique_id = technique['id']
            technique_name = technique['name']
            
            print(f"\n=== Analyzing technique {technique_id}: {technique_name} ===")
            
            # Create output filename
            filename = f"{technique_id}-{technique_name.lower().replace(' ', '_').replace('(', '').replace(')', '')}_refined.txt"
            related_modules = []
            
            # Analyze each module
            for i, module_path in enumerate(all_modules):
                if i % 100 == 0:
                    print(f"  Processed {i}/{len(all_modules)} modules...")
                
                is_related, reasoning = self.analyze_module_for_technique(module_path, technique)
                
                if is_related:
                    rel_module_path = str(Path(module_path).relative_to(self.modules_path))
                    doc_path = self.get_module_documentation_path(module_path)
                    doc_path_str = str(doc_path.relative_to(self.repo_path)) if doc_path else "No documentation found"
                    
                    related_modules.append({
                        'module': rel_module_path,
                        'doc_path': doc_path_str,
                        'reasoning': reasoning
                    })
                    
                    print(f"    MATCH: {rel_module_path}")
                    print(f"           {reasoning}")
            
            # Write results to file
            with open(filename, 'w') as f:
                f.write(f"MITRE ATT&CK Technique: {technique_id} - {technique_name}\n")
                f.write(f"Tactic: {technique['tactic']}\n")
                f.write(f"Description: {technique['description']}\n")
                f.write(f"\nTotal related modules found: {len(related_modules)}\n")
                f.write("="*80 + "\n\n")
                
                for module_info in sorted(related_modules, key=lambda x: x['reasoning'], reverse=True):
                    f.write(f"Module: {module_info['module']}\n")
                    f.write(f"Documentation: {module_info['doc_path']}\n")
                    f.write(f"Analysis: {module_info['reasoning']}\n")
                    f.write("-" * 40 + "\n\n")
            
            print(f"  Created {filename} with {len(related_modules)} related modules")

def main():
    repo_path = "/home/runner/work/metasploit-framework/metasploit-framework"
    csv_path = "/home/runner/work/metasploit-framework/metasploit-framework/mitre1.csv"
    
    categorizer = RefinedModuleCategorizer(repo_path, csv_path)
    categorizer.categorize_modules()

if __name__ == "__main__":
    main()