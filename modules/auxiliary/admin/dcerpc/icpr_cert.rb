##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb/dcerpc/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MsAdcs

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ICPR Certificate Management',
        'Description' => %q{
          Request certificates via MS-ICPR (Active Directory Certificate Services). Depending on the certificate
          template's configuration the resulting certificate can be used for various operations such as authentication.
          PFX certificate files that are saved are encrypted with a blank password.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Oliver Lyak', # certipy implementation
          'Spencer McIntyre',
        ],
        'References' => [
        ],
        'Notes' => {
          'Reliability' => [],
          'Stability' => [],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'Actions' => [
          [ 'REQUEST_CERT', { 'Description' => 'Request a certificate' } ]
        ],
        'DefaultAction' => 'REQUEST_CERT'
      )
    )
  end

  def run
    send("action_#{action.name.downcase}")
  rescue MsAdcsConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue MsAdcsAuthentcationError => e
    fail_with(Failure::NoAccess, e.message)
  rescue MsAdcsNotFoundError => e
    fail_with(Failure::NotFound, e.message)
  rescue MsAdcsUnexpectedReplyError => e
    fail_with(Failure::UnexpectedReply, e.message)
  rescue MsAdcsUnknownError => e
    fail_with(Failure::Unknown, e.message)
  end

  def action_request_cert
    request_certificate
  end

end
