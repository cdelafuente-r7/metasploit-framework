#!/usr/bin/env ruby
# frozen_string_literal: true

# Generate a summary report of the MITRE technique categorization.

require 'csv'

def generate_summary
  puts "MITRE ATT&CK Technique Categorization Summary"
  puts "=" * 60
  
  # Read CSV to get technique details
  techniques = {}
  CSV.foreach('/home/runner/work/metasploit-framework/metasploit-framework/mitre1.csv', headers: true) do |row|
    if row['MSF Tag Priority']&.strip&.downcase == 'high'
      techniques[row['Technique ID']&.strip] = {
        'name' => row['Technique Name']&.strip,
        'tactic' => row['Tactic']&.strip,
        'description' => row['Description']&.strip
      }
    end
  end
  
  puts "\nAnalyzed #{techniques.length} high priority MITRE ATT&CK techniques:"
  techniques.each do |tid, details|
    puts "  #{tid}: #{details['name']} (#{details['tactic']})"
  end
  
  puts "\nResults Summary:"
  puts "-" * 40
  
  total_modules = 0
  
  # Process refined results
  Dir.glob('/home/runner/work/metasploit-framework/metasploit-framework/T*_refined.txt').sort.each do |filename|
    content = File.read(filename)
    
    # Extract technique ID from filename
    technique_match = filename.match(/T(\d{4})/)
    if technique_match
      tid = "T#{technique_match[1]}"
      
      # Count modules
      module_count = content.scan(/Module: /).length
      total_modules += module_count
      
      # Get technique details
      tech_details = techniques[tid] || {'name' => 'Unknown', 'tactic' => 'Unknown'}
      
      puts "#{tid} - #{tech_details['name']}"
      puts "  Tactic: #{tech_details['tactic']}"
      puts "  Related modules found: #{module_count}"
      puts "  Output file: #{File.basename(filename)}"
      puts "  Paths file: #{File.basename(filename).gsub('_refined.txt', '_paths.txt')}"
      puts
    end
  end
  
  puts "Total modules categorized across all techniques: #{total_modules}"
  puts "\nNote: Some modules may be categorized under multiple techniques."
  
  # Show top 5 modules for T1003 as example
  puts "\nExample: Top 5 modules for T1003 (OS Credential Dumping):"
  puts "-" * 50
  
  begin
    content = File.read('/home/runner/work/metasploit-framework/metasploit-framework/T1003-os_credential_dumping_refined.txt')
    
    modules = content.scan(/Module: ([^\n]+)\nDocumentation: ([^\n]+)\nAnalysis: ([^\n]+)/)
    
    modules.first(5).each_with_index do |(mod, doc, analysis), i|
      puts "#{i+1}. #{mod}"
      puts "   Documentation: #{doc}"
      puts "   #{analysis}"
      puts
    end
  rescue Errno::ENOENT
    puts "T1003 results file not found. Run categorization first."
  end
end

if __FILE__ == $0
  generate_summary
end