module Msf
module Util
module WindowsRegistry

  class LocalRegistry
    include Msf::Post::Windows::Registry

    attr_reader :session

    def initialize(session)
      @session = session
    end

    def key_exists?(key)
      registry_key_exist?(key)
    end

    def enum_values(key)
      registry_enumvals(key)
    end

    def get_value(key, value_name = nil)
      # TODO: handle views (native, 64bits, 32bits)
      registry_getvaldata(key, value_name)
    end

    def enum_key(key)
      registry_enumkeys(key)
    end

  end
end
end
end

