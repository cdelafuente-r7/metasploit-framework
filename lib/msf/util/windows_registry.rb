module Msf::Util::WindowsRegistry

  def self.remote_connect(winreg, name: nil, inline: false)
    RemoteRegistry.new(winreg, name: name, inline: inline)
  end

  def self.local_connect(session)
    LocalRegistry.new(session)
  end

  def self.parse(hive_data, name: nil, root: nil)
    RegistryParser.new(hive_data, name: name, root: root)
  end

end
