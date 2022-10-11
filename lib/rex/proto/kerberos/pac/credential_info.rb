# -*- coding: binary -*-

module RubySMB::Dcerpc::Ndr

  # [2.2.6.1 Common Type Header for the Serialization Stream](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/6d75d40e-e2d2-4420-b9e9-8508a726a9ae)
  class TypeSerialization1CommonTypeHeader < NdrStruct
    default_parameter byte_align: 8
    endian :little

    ndr_uint8  :version, initial_value: 1
    ndr_uint8  :endianness, initial_value: 0x10
    ndr_uint16 :common_header_length, initial_value: 8
    ndr_uint32 :filler, initial_value: 0xCCCCCCCC
  end

  # [2.2.6.2 Private Header for Constructed Type](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/63949ba8-bc88-4c0c-9377-23f14b197827)
  class TypeSerialization1PrivateHeader < NdrStruct
    default_parameter byte_align: 8
    endian :little

    ndr_uint32 :object_buffer_length
    ndr_uint32 :filler, initial_value: 0x00000000
  end

  # [2.2.6 Type Serialization Version 1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/9a1d0f97-eac0-49ab-a197-f1a581c2d6a0)
  class TypeSerialization1 < NdrStruct
    default_parameter byte_align: 4
    endian :little
    search_prefix :type_serialization1

    common_type_header  :common_header
    private_header      :private_header
  end
end

module Rex
  module Proto
    module Kerberos
      module Pac
        # This class provides a representation of a PAC-CREDENTIAL-INFO
        # structure, containing the credential information. It indicates the
        # encryption algorithm that was used to encrypt the data that follows
        # it.
        class CredentialInfo < Element

          # @!attribute version
          #   @return [Integer] The version
          attr_accessor :version
          # @!attribute encryption_type
          #   @return [Integer] The Kerberos encryption type used to encode the
          #     :serialized_data array
          attr_accessor :encryption_type
          # @!attribute serialized_data
          #   @return [String] The encrypted PAC_CREDENTIAL_DATA structure that
          #     contains credentials encrypted using the mechanism specified by
          #     the EncryptionType field
          attr_accessor :serialized_data

          class NtlmSupplementalCredential < RubySMB::Dcerpc::Ndr::NdrStruct
            default_parameter byte_align: 4
            endian :little

            ndr_uint32 :version
            ndr_uint32 :flags
            ndr_fixed_byte_array :lm_password, initial_length: 16
            ndr_fixed_byte_array :nt_password, initial_length: 16
          end

          class SecpkgSupplementalCredByteArrayPtr < RubySMB::Dcerpc::Ndr::NdrConfArray
            default_parameters type: :ndr_uint8
            extend RubySMB::Dcerpc::Ndr::PointerClassPlugin
          end

          class SecpkgSupplementalCred < RubySMB::Dcerpc::Ndr::NdrStruct
            default_parameter byte_align: 4
            endian :little

            rpc_unicode_string :package_name
            ndr_uint32 :credential_size
            secpkg_supplemental_cred_byte_array_ptr :credentials
          end

          class PacCredentialData < RubySMB::Dcerpc::Ndr::NdrStruct
            default_parameter byte_align: 4
            endian :little

            ndr_uint32 :credential_count
            ndr_conf_array :credentials, type: :secpkg_supplemental_cred
          end

          class PacCredentialDataPtr < PacCredentialData
            extend RubySMB::Dcerpc::Ndr::PointerClassPlugin
          end

          class SerializedPacCredentialData < BinData::Record
            endian :little

            type_serialization1 :type_serialization1
            pac_credential_data_ptr :data
          end

          class PacCredentialInfo < BinData::Record
            endian :little

            uint32 :version
            uint32 :encryption_type
            array  :serialized_data, type: :uint8, read_until: :eof
          end

          # Decodes the Rex::Proto::Kerberos::Pac::CredentialInfo from an input
          #
          # @param input [String] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode(input)
            cred_info = PacCredentialInfo.read(input)
            self.version = cred_info.version.to_i
            self.encryption_type = cred_info.encryption_type.to_i
            self.serialized_data = cred_info.serialized_data.to_binary_s
            self
          end

          def decrypt_serialized_data(key)
            encryptor = Rex::Proto::Kerberos::Crypto::Encryption::from_etype(encryption_type)
            decrypted_serialized_data = encryptor.decrypt(
              serialized_data,
              key,
              Rex::Proto::Kerberos::Crypto::KeyUsage::KERB_NON_KERB_SALT
            )
            SerializedPacCredentialData.read(decrypted_serialized_data)
          end

          def extract_ntlm_hash(serialized_pac_credential_data)
            serialized_pac_credential_data.data.credentials.each do |credential|
              if credential.package_name.to_s == 'NTLM'.encode('utf-16le')
                ntlm_creds_raw = credential.credentials.to_ary.pack('C*')
                ntlm_creds = NtlmSupplementalCredential.read(ntlm_creds_raw)
                if ntlm_creds.lm_password.any? {|elem| elem != 0}
                  lm_hash = ntlm_creds.lm_password.to_hex
                else
                  lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
                end
                nt_hash = ntlm_creds.nt_password.to_hex

                puts "Found NTML hash: #{lm_hash}:#{nt_hash}"
              end
            end
          end

          #private

          # Decodes the version from a string
          #
          # @param input [String] the input to decode from
          #def decode_version(input)
          #  input.unpack1('V')
          #end

          ## Decodes the encryption_type from a string
          ##
          ## @param input [String] the input to decode from
          #def decode_encryption_type(input)
          #  input.unpack1('V')
          #end

        end
      end
    end
  end
end


