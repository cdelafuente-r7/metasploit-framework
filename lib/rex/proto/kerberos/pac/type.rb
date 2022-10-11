# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Pac
        # This class provides a representation of a PAC_TYPE structure, the topmost structure
        # of the PAC.
        class Type < Element

          # @!attribute buffers
          #   @return [Array<Rex::Proto::Kerberos::Pac::Element>] The array of PAC_INFO_BUFFER structures
          attr_accessor :buffers
          # @!attribute checksum
          #   @return [Integer] The type of checksum to use when encoding PAC-TYPE
          attr_accessor :checksum

          # Key used to create the checksum
          attr_accessor :key

          class PacInfoBuffer < BinData::Record
            endian :little

            uint32 :ul_type
            uint32 :cb_buffer_size
            uint64 :offset
          end

          class PacType < BinData::Record
            endian :little

            uint32 :c_buffers, initial_value: -> { buffers.size }
            uint32 :version
            array  :info_buffers, type: :pac_info_buffer, read_until: -> { index == c_buffers - 1 }
            array  :raw_buffer, type: :uint8, read_until: :eof

            def buffers
              result = []
              info_buffers.each do |info_buffer|
                offset = info_buffer.offset - raw_buffer.abs_offset
                case info_buffer.ul_type
                when PAC_CLIENT_INFO
                  # TODO
                  #result << ClientInfo.decode(raw_buffer[offset, info_buffer.cb_buffer_size)
                when PAC_LOGON_INFO
                  # TODO
                  #result << LogonInfo.decode(raw_buffer[offset, info_buffer.cb_buffer_size)
                when PAC_PRIVSVR_CHECKSUM
                  # TODO
                  #result << PrivSvrChecksum.decode(raw_buffer[offset, info_buffer.cb_buffer_size)
                when PAC_SERVER_CHECKSUM
                  # TODO
                  #result << ServerChecksum.decode(raw_buffer[offset, info_buffer.cb_buffer_size)
                when PAC_CREDENTIALS_INFO
                  credential_info = CredentialInfo.new
                  result << credential_info.decode(raw_buffer.to_binary_s[offset, info_buffer.cb_buffer_size])
                end
              end

              result
            end
          end

          # Decodes the Rex::Proto::Kerberos::Pac::Type from an input
          #
          # @param input [String] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode(input)
            pac_type = PacType.read(input)
            self.buffers = pac_type.buffers
            self
          end

          # Decodes the buffers_length from a string
          #
          # @param input [String] the input to decode from
          def decode_buffers_length(input)
            input.unpack1('V')
          end

          # Decodes the version from a string
          #
          # @param input [String] the input to decode from
          def decode_version(input)
            input.unpack1('V')
          end

          # Decodes the PAC_INFO_BUFFER's from a string
          #
          # @param input [String] the input to decode from
          def decode_pac_info_buffers(input)
            offset = 8 + buffers.length * 16
            encoded = ''
            buffers.each do |buffer|
              case buffer
              when ClientInfo
                encoded << [PAC_CLIENT_INFO].pack('V')
              when LogonInfo
                encoded << [PAC_LOGON_INFO].pack('V')
              when PrivSvrChecksum
                encoded << [PAC_PRIVSVR_CHECKSUM].pack('V')
              when ServerChecksum
                encoded << [PAC_SERVER_CHECKSUM].pack('V')
              when CredentialInfo
                encoded << [PAC_CREDENTIALS_INFO].pack('V')
              end

              buffer_length = buffer.encode.length

              encoded << [buffer_length].pack('V')
              encoded << [offset].pack('Q<')

              offset = (offset + buffer_length + 7) / 8 * 8
            end

            encoded
          end

          # Encodes the Rex::Proto::Kerberos::Pac::Type
          #
          # @return [String]
          def encode
            offset_one = 0
            offset_two = 0

            draft = ''
            draft << encode_buffers_length
            draft << encode_version
            draft << encode_pac_info_buffers

            # Encode buffers
            buffers.each do |buffer|
              if buffer.class == ServerChecksum
                offset_one = draft.length + 4
              elsif buffer.class == PrivSvrChecksum
                offset_two = draft.length + 4
              end

              buffer_encoded = buffer.encode
              draft << buffer_encoded
              draft << "\x00" * ((buffer_encoded.length + 7) / 8 * 8 - buffer_encoded.length)
            end

            checksum_draft = make_checksum(draft)
            double_checksum = make_checksum(checksum_draft)

            encoded = ''
            encoded << draft[0..(offset_one - 1)]
            encoded << checksum_draft
            encoded << draft[(offset_one + checksum_draft.length)..(offset_two - 1)]
            encoded << double_checksum
            encoded << draft[(offset_two + double_checksum.length)..(draft.length - 1)]

            encoded
          end

          private

          # Encodes the number of buffers contained in the PAC
          #
          # @return [String]
          def encode_buffers_length
            [buffers.length].pack('V')
          end

          # Encodes the PAC version
          #
          # @return [String]
          def encode_version
            [VERSION].pack('V')
          end

          # Encodes the PAC_INFO_BUFFER data
          #
          # @return [String]
          def encode_pac_info_buffers
            offset = 8 + buffers.length * 16
            encoded = ''
            buffers.each do |buffer|
              case buffer
              when ClientInfo
                encoded << [PAC_CLIENT_INFO].pack('V')
              when LogonInfo
                encoded << [PAC_LOGON_INFO].pack('V')
              when PrivSvrChecksum
                encoded << [PAC_PRIVSVR_CHECKSUM].pack('V')
              when ServerChecksum
                encoded << [PAC_SERVER_CHECKSUM].pack('V')
              when CredentialInfo
                encoded << [PAC_CREDENTIALS_INFO].pack('V')
              end

              buffer_length = buffer.encode.length

              encoded << [buffer_length].pack('V')
              encoded << [offset].pack('Q<')

              offset = (offset + buffer_length + 7) / 8 * 8
            end

            encoded
          end

          # Calculates the checksum for the PAC data
          #
          # @param data [String] the data to checksum
          # @return [String] the checksum result
          # @raise [NotImplementedError] if checksum schema isn't supported
          def make_checksum(data)
            checksummer = Rex::Proto::Kerberos::Crypto::Checksum::from_checksum_type(checksum)

            checksummer.checksum(self.key, Rex::Proto::Kerberos::Crypto::KeyUsage::KERB_NON_KERB_CKSUM_SALT, data)
          end
        end
      end
    end
  end
end
