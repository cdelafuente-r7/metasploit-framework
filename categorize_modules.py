#!/usr/bin/env python3
"""
Script to categorize Metasploit modules by MITRE ATT&CK techniques.
"""

import csv
import os
import re
import glob
from pathlib import Path

class ModuleCategorizer:
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
        # Convert module path to documentation path
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
        """Read and parse a module file to extract description and options."""
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
            
            # Also look for Name field
            name = ""
            name_match = re.search(r"'Name'\s*=>\s*['\"]([^'\"]+)['\"]", content)
            if name_match:
                name = name_match.group(1).strip()
            
            return {
                'name': name,
                'description': description,
                'content': content[:2000]  # First 2000 chars for analysis
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
            print(f"Error reading documentation {doc_path}: {e}")
            return None
    
    def analyze_module_for_technique(self, module_path, technique):
        """Analyze if a module relates to a specific MITRE technique."""
        module_info = self.read_module_file(module_path)
        if not module_info:
            return False, "Could not read module file"
        
        doc_path = self.get_module_documentation_path(module_path)
        doc_content = ""
        if doc_path:
            doc_content = self.read_documentation_file(doc_path) or ""
        
        # Analysis based on technique
        technique_id = technique['id']
        technique_name = technique['name'].lower()
        technique_desc = technique['description'].lower()
        
        analysis_text = (module_info['name'] + " " + module_info['description'] + " " + 
                        module_info['content'] + " " + doc_content).lower()
        
        # Define keywords for each technique
        technique_keywords = {
            'T1003': ['credential', 'dump', 'hash', 'password', 'lsa', 'sam', 'ntds', 'secrets', 'mimikatz'],
            'T1021': ['remote', 'login', 'ssh', 'rdp', 'smb', 'winrm', 'telnet', 'vnc'],
            'T1055': ['inject', 'process', 'dll', 'shellcode', 'memory'],
            'T1059': ['command', 'script', 'shell', 'powershell', 'cmd', 'bash', 'interpreter'],
            'T1110': ['brute', 'force', 'login', 'password', 'dictionary', 'crack'],
            'T1190': ['exploit', 'vulnerability', 'cve', 'remote', 'web', 'application'],
            'T1210': ['exploit', 'remote', 'service', 'vulnerability', 'lateral'],
        }
        
        keywords = technique_keywords.get(technique_id, [])
        keywords.extend(technique_name.split())
        
        # Count keyword matches
        matches = 0
        matched_keywords = []
        for keyword in keywords:
            if keyword in analysis_text:
                matches += 1
                matched_keywords.append(keyword)
        
        # Determine if module is related (threshold: at least 2 keyword matches)
        is_related = matches >= 2
        
        reasoning = f"Found {matches} keyword matches: {', '.join(matched_keywords)}"
        if doc_path:
            reasoning += f" (analyzed module source and documentation at {doc_path})"
        else:
            reasoning += " (analyzed module source only, no documentation found)"
        
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
            filename = f"{technique_id}-{technique_name.lower().replace(' ', '_').replace('(', '').replace(')', '')}.txt"
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
                    print(f"           Doc: {doc_path_str}")
                    print(f"           Reason: {reasoning}")
            
            # Write results to file
            with open(filename, 'w') as f:
                f.write(f"MITRE ATT&CK Technique: {technique_id} - {technique_name}\n")
                f.write(f"Tactic: {technique['tactic']}\n")
                f.write(f"Description: {technique['description']}\n")
                f.write(f"\nTotal related modules found: {len(related_modules)}\n")
                f.write("="*80 + "\n\n")
                
                for module_info in related_modules:
                    f.write(f"Module: {module_info['module']}\n")
                    f.write(f"Documentation: {module_info['doc_path']}\n")
                    f.write(f"Analysis: {module_info['reasoning']}\n")
                    f.write("-" * 40 + "\n\n")
            
            print(f"  Created {filename} with {len(related_modules)} related modules")

def main():
    repo_path = "/home/runner/work/metasploit-framework/metasploit-framework"
    csv_path = "/home/runner/work/metasploit-framework/metasploit-framework/mitre1.csv"
    
    categorizer = ModuleCategorizer(repo_path, csv_path)
    categorizer.categorize_modules()

if __name__ == "__main__":
    main()