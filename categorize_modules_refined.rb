#!/usr/bin/env ruby
# frozen_string_literal: true

# Refined script to categorize Metasploit modules by MITRE ATT&CK techniques.
# Uses more precise analysis with weighted keywords and context.

require 'csv'
require 'json'
require 'net/http'
require 'uri'
require 'pathname'

class RefinedModuleCategorizer
  def initialize(repo_path, csv_path, opts = {})
    @repo_path = Pathname.new(repo_path)
    @csv_path = csv_path
    @modules_path = @repo_path / "modules"
    @docs_path = @repo_path / "documentation" / "modules"
    @web_query = opts[:web_query] || false
  end

  def read_mitre_csv
    # Read the MITRE CSV file and return high priority techniques
    high_priority_techniques = []

    CSV.foreach(@csv_path, headers: true) do |row|
      if row['MSF Tag Priority']&.strip&.downcase == 'high'
        high_priority_techniques << {
          'id' => row['Technique ID']&.strip,
          'name' => row['Technique Name']&.strip,
          'description' => row['Description']&.strip,
          'tactic' => row['Tactic']&.strip
        }
      end
    end

    high_priority_techniques
  end

  def get_modules(limit = nil)
    # Get all module files in the repository
    module_files = []
    ['rb', 'py'].each do |ext|
      pattern = @modules_path / "**/*.#{ext}"
      module_files.concat(Dir.glob(pattern.to_s))
    end
    limit ? module_files.first(limit) : module_files
  end

  def get_module_documentation_path(module_path)
    # Get the corresponding documentation path for a module
    rel_path = Pathname.new(module_path).relative_path_from(@modules_path)

    # Convert plural directory names to singular for documentation
    parts = rel_path.to_s.split('/')
    if parts.length > 0
      # Handle the type conversion (e.g., exploits -> exploit)
      if parts[0].end_with?('s') && parts[0] != 'post'
        parts[0] = parts[0][0..-2]  # Remove trailing 's'
      end
    end

    # Change extension to .md
    if parts[-1].end_with?('.rb') || parts[-1].end_with?('.py')
      parts[-1] = parts[-1].split('.')[0..-2].join('.') + '.md'
    end

    doc_path = @docs_path / parts.join('/')
    doc_path.exist? ? doc_path : nil
  end

  def query_cve_api(cve_id)
    # Query the CVE API to get CVE information
    # Note: Disabled in current environment due to network restrictions
    begin
      uri = URI("https://cveawg.mitre.org/api/cve/#{cve_id}")
      response = Net::HTTP.get_response(uri)

      if response.code == '200'
        JSON.parse(response.body)
      else
        puts "[ERROR] CVE API returned #{response.code} for #{cve_id}"
        nil
      end
    rescue => e
      puts "[ERROR] Exception querying CVE API for #{cve_id}: #{e.message}"
      nil
    end
  end

  def extract_cve_references(content)
    # Extract CVE references in the format ['CVE', '2017-4915']
    cve_refs = []

    # Look for the pattern ['CVE', 'YYYY-NNNN'] or ["CVE", "YYYY-NNNN"]
    matches = content.scan(/\[\s*['"]CVE['"],\s*['"](\d{4}-\d+)['"]\s*\]/i)
    matches.each do |match|
      cve_id = "CVE-#{match[0]}"
      cve_refs << cve_id
    end

    cve_refs.uniq
  end

  def analyze_cve_descriptions(cve_refs, technique)
    # Analyze CVE descriptions for technique relevance
    cve_analysis = []

    cve_refs.each do |cve_id|
      cve_data = query_cve_api(cve_id)
      next unless cve_data && cve_data['containers'] && cve_data['containers']['cna']

      description = ""
      if cve_data['containers']['cna']['descriptions']
        desc_obj = cve_data['containers']['cna']['descriptions'].find { |d| d['lang'] == 'en' }
        description = desc_obj['value'] if desc_obj
      end

      if description && !description.empty?
        score = analyze_cve_description_for_technique(description, technique)
        if score > 0
          cve_analysis << {
            'cve_id' => cve_id,
            'description' => description,
            'score' => score
          }
        end
      end
    end

    cve_analysis
  end

  def analyze_cve_description_for_technique(description, technique)
    # Analyze CVE description for technique-specific keywords
    technique_id = technique['id']
    desc_lower = description.downcase

    # Define technique-specific keywords for CVE analysis
    cve_keywords = {
      'T1003' => ['credential', 'password', 'hash', 'dump', 'extract', 'steal'],
      'T1021' => ['remote', 'ssh', 'rdp', 'smb', 'winrm', 'telnet', 'vnc', 'login'],
      'T1055' => ['injection', 'inject', 'process', 'dll', 'memory', 'shellcode'],
      'T1059' => ['execution', 'execute', 'command', 'script', 'shell', 'powershell'],
      'T1110' => ['brute', 'force', 'password', 'login', 'authentication', 'crack'],
      'T1190' => ['exploit', 'vulnerability', 'web', 'application', 'remote'],
      'T1210' => ['exploit', 'service', 'remote', 'vulnerability', 'lateral']
    }

    keywords = cve_keywords[technique_id] || []
    score = 0

    keywords.each do |keyword|
      score += 2 if desc_lower.include?(keyword)
    end

    score
  end

  def validate_module_with_ai(technique, cve_refs, module_path, module_content, doc_content)
    # AI validation method - currently disabled, needs API configuration
    # This method will be activated when AI API details are provided
    
    # Construct ATT&CK technique URL
    technique_url = "https://attack.mitre.org/techniques/#{technique['id']}"
    
    # Prepare CVE URLs
    cve_urls = cve_refs.map { |cve| "https://cveawg.mitre.org/api/cve/#{cve}" }
    
    # Prepare validation request data
    validation_data = {
      technique: {
        id: technique['id'],
        name: technique['name'],
        url: technique_url
      },
      cve_urls: cve_urls,
      module: {
        path: module_path,
        content: module_content
      },
      documentation: doc_content
    }
    
    # TODO: Implement AI API call when configuration is provided
    # For now, return true (allow all modules through)
    # When implemented, this should return true/false based on AI validation
    
    puts "[INFO] AI validation disabled - module passed through without validation"
    return true
  end

  def read_module_file(module_path)
    # Read and parse a module file to extract key information
    begin
      content = File.read(module_path, encoding: 'UTF-8')

      # Extract description from update_info method
      description = ""
      info_match = content.match(/update_info\s*\(\s*info,\s*\{([^}]+)\}/m)
      if info_match
        info_content = info_match[1]
        desc_match = info_content.match(/'Description'\s*=>\s*%q\{([^}]+)\}/m)
        description = desc_match[1].strip if desc_match
      end

      # Extract Name field
      name = ""
      name_match = content.match(/'Name'\s*=>\s*['"]([^'"]+)['"]/)
      name = name_match[1].strip if name_match

      # Extract References
      references = []
      ref_matches = content.scan(/'URL',\s*['"]([^'"]+)['"]/)
      references.concat(ref_matches.flatten)

      # Extract CVE references
      cve_refs = extract_cve_references(content)

      {
        'name' => name,
        'description' => description,
        'references' => references,
        'content' => content,
        'cve_refs' => cve_refs
      }
    rescue => e
      puts "Error reading #{module_path}: #{e.message}"
      nil
    end
  end

  def read_documentation_file(doc_path)
    # Read module documentation file
    begin
      File.read(doc_path, encoding: 'UTF-8')
    rescue => e
      nil
    end
  end

  def analyze_module_for_technique(module_path, technique)
    # Analyze if a module relates to a specific MITRE technique with refined scoring
    module_info = read_module_file(module_path)
    return [false, "Could not read module file"] unless module_info

    doc_path = get_module_documentation_path(module_path)
    doc_content = ""
    if doc_path
      doc_content = read_documentation_file(doc_path) || ""
    end

    technique_id = technique['id']

    # Create analysis text (prioritize name and description)
    name_desc = (module_info['name'] + " " + module_info['description']).downcase
    full_content = (module_info['content'] + " " + doc_content).downcase

    score = 0
    matched_indicators = []

    # Define highly specific indicators for each technique
    technique_indicators = {
      'T1003' => {
        'high_value' => ['credential dump', 'hash dump', 'lsass', 'sam dump', 'ntds.dit', 
                        'mimikatz', 'hashdump', 'cachedump', 'lsa secrets', 'password hash'],
        'medium_value' => ['credential', 'password extract', 'hash extract', 'secrets'],
        'low_value' => ['dump', 'hash', 'password'],
        'path_indicators' => ['gather', 'hashdump', 'cachedump', 'lsa', 'sam']
      },
      'T1021' => {
        'high_value' => ['remote login', 'ssh login', 'rdp login', 'smb login', 'winrm login',
                        'telnet login', 'vnc login', 'remote service', 'lateral movement'],
        'medium_value' => ['ssh', 'rdp', 'smb', 'winrm', 'telnet', 'vnc', 'remote'],
        'low_value' => ['login', 'connect', 'service'],
        'path_indicators' => ['ssh', 'rdp', 'smb', 'winrm', 'telnet', 'vnc', 'login']
      },
      'T1055' => {
        'high_value' => ['process injection', 'dll injection', 'shellcode injection', 
                        'code injection', 'memory injection', 'process hollowing'],
        'medium_value' => ['inject', 'dll', 'shellcode', 'memory'],
        'low_value' => ['process', 'memory'],
        'path_indicators' => ['inject', 'dll', 'memory', 'process']
      },
      'T1059' => {
        'high_value' => ['command execution', 'script execution', 'shell execution',
                        'powershell', 'cmd execution', 'bash execution'],
        'medium_value' => ['command', 'script', 'shell', 'execute', 'run'],
        'low_value' => ['cmd', 'bash', 'powershell'],
        'path_indicators' => ['cmd', 'shell', 'exec', 'script', 'powershell']
      },
      'T1110' => {
        'high_value' => ['brute force', 'password brute', 'login brute', 'dictionary attack',
                        'password crack', 'credential brute'],
        'medium_value' => ['brute', 'crack', 'dictionary', 'wordlist'],
        'low_value' => ['login', 'password', 'force'],
        'path_indicators' => ['brute', 'login', 'crack', 'dict']
      },
      'T1190' => {
        'high_value' => ['web exploit', 'web vulnerability', 'cve-', 'remote exploit',
                        'public application', 'http exploit'],
        'medium_value' => ['exploit', 'vulnerability', 'cve', 'web'],
        'low_value' => ['http', 'web', 'remote'],
        'path_indicators' => ['http', 'web', 'exploit', 'cve']
      },
      'T1210' => {
        'high_value' => ['remote service exploit', 'service exploitation', 'lateral movement',
                        'remote vulnerability', 'service attack'],
        'medium_value' => ['remote', 'service', 'exploit', 'lateral'],
        'low_value' => ['service', 'remote'],
        'path_indicators' => ['service', 'remote', 'lateral', 'exploit']
      }
    }

    indicators = technique_indicators[technique_id] || {}

    # Score high-value indicators in name/description (highest weight)
    (indicators['high_value'] || []).each do |indicator|
      if name_desc.include?(indicator)
        score += 10
        matched_indicators << "HIGH: '#{indicator}' in name/description"
      end
    end

    # Score medium-value indicators in name/description
    (indicators['medium_value'] || []).each do |indicator|
      if name_desc.include?(indicator)
        score += 5
        matched_indicators << "MED: '#{indicator}' in name/description"
      end
    end

    # Score high-value indicators in full content (lower weight)
    (indicators['high_value'] || []).each do |indicator|
      if full_content.include?(indicator)
        score += 3
        matched_indicators << "HIGH: '#{indicator}' in content"
      end
    end

    # Score path indicators (module path suggests relevance)
    module_path_lower = module_path.downcase
    (indicators['path_indicators'] || []).each do |indicator|
      if module_path_lower.include?(indicator)
        score += 2
        matched_indicators << "PATH: '#{indicator}' in module path"
      end
    end

    # Check for MITRE references in the module
    module_info['references'].each do |ref|
      if ref.downcase.include?(technique_id.downcase) || ref.downcase.include?('mitre.org')
        score += 15
        matched_indicators << "MITRE: MITRE reference found: #{ref}"
      end
    end

    # Analyze CVE references if present
    if !module_info['cve_refs'].empty? && @web_query
      cve_analysis = analyze_cve_descriptions(module_info['cve_refs'], technique)
      cve_analysis.each do |cve_info|
        score += cve_info['score']
        matched_indicators << "CVE: #{cve_info['cve_id']} analysis contributes #{cve_info['score']} points"
      end
    end

    # Set threshold for inclusion (more restrictive)
    is_related = score >= 5

    reasoning = "Score: #{score} - " + matched_indicators.first(5).join("; ")  # Show top 5 matches
    if doc_path
      reasoning += " (analyzed module source and documentation)"
    else
      reasoning += " (analyzed module source only)"
    end

    [is_related, reasoning]
  end

  def categorize_modules
    # Main method to categorize all modules by high priority techniques
    puts "Reading MITRE techniques from CSV..."
    techniques = read_mitre_csv

    puts "Found #{techniques.length} high priority techniques:"
    techniques.each do |tech|
      puts "  #{tech['id']}: #{tech['name']}"
    end

    puts "\nGetting all modules..."
    all_modules = get_modules
    puts "Found #{all_modules.length} modules to analyze"

    # Process each technique
    techniques.each do |technique|
      technique_id = technique['id']
      technique_name = technique['name']

      puts "\n=== Analyzing technique #{technique_id}: #{technique_name} ==="

      # Create output filename
      filename = "#{technique_id}-#{technique_name.downcase.gsub(' ', '_').gsub(/[()]/, '')}_refined.txt"
      path_filename = "#{technique_id}-#{technique_name.downcase.gsub(' ', '_').gsub(/[()]/, '')}_paths.txt"
      related_modules = []
      module_paths = []

      # Analyze each module
      all_modules.each_with_index do |module_path, i|
        if i % 100 == 0
          puts "  Processed #{i}/#{all_modules.length} modules..."
        end

        is_related, reasoning = analyze_module_for_technique(module_path, technique)

        if is_related
          # Get module information for AI validation
          module_info = read_module_file(module_path)
          next unless module_info  # Skip if we can't read the module
          
          # Get documentation content
          doc_path = get_module_documentation_path(module_path)
          doc_content = ""
          if doc_path
            doc_content = read_documentation_file(doc_path) || ""
          end
          
          # Check if there are CVE references and perform AI validation if configured
          cve_refs = module_info['cve_refs'] || []
          
          # Perform AI validation if CVEs are present
          if !cve_refs.empty?
            ai_validated = validate_module_with_ai(technique, cve_refs, module_path, module_info['content'], doc_content)
            
            # Skip this module if AI validation fails
            unless ai_validated
              puts "    SKIPPED: #{Pathname.new(module_path).relative_path_from(@repo_path).to_s} - AI validation failed"
              next
            end
          end
          
          rel_module_path = Pathname.new(module_path).relative_path_from(@repo_path).to_s
          doc_path_str = doc_path ? doc_path.relative_path_from(@repo_path).to_s : "No documentation found"

          related_modules << {
            'module' => rel_module_path,
            'doc_path' => doc_path_str,
            'reasoning' => reasoning
          }

          module_paths << rel_module_path

          puts "    MATCH: #{rel_module_path}"
          puts "           #{reasoning}"
        end
      end

      # Write detailed results to file
      File.open(filename, 'w') do |f|
        f.puts "MITRE ATT&CK Technique: #{technique_id} - #{technique_name}"
        f.puts "Tactic: #{technique['tactic']}"
        f.puts "Description: #{technique['description']}"
        f.puts "\nTotal related modules found: #{related_modules.length}"
        f.puts "=" * 80
        f.puts

        related_modules.sort_by { |x| x['reasoning'] }.reverse.each do |module_info|
          f.puts "Module: #{module_info['module']}"
          f.puts "Documentation: #{module_info['doc_path']}"
          f.puts "Analysis: #{module_info['reasoning']}"
          f.puts "-" * 40
          f.puts
        end
      end

      # Write module paths only to separate file
      File.open(path_filename, 'w') do |f|
        module_paths.sort.each do |path|
          f.puts path
        end
      end

      puts "  Created #{filename} with #{related_modules.length} related modules"
      puts "  Created #{path_filename} with module paths only"
    end
  end
end

def main
  repo_path = '/home/runner/work/metasploit-framework/metasploit-framework'
  opts = { web_query: false }
  if ARGV[0] && !ARGV[0].empty?
    repo_path = ARGV[0]
    opts[:web_query] = true
  end
  csv_path = "#{repo_path}/mitre1.csv"

  categorizer = RefinedModuleCategorizer.new(repo_path, csv_path, opts)
  categorizer.categorize_modules
end

if __FILE__ == $0
  main
end
