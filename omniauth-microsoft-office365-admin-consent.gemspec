# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/microsoft_office365_admin_consent/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-microsoft-office365-admin-consent"
  spec.version       = OmniAuth::MicrosoftOffice365AdminConsent::VERSION
  spec.authors       = ["Yuta Morinaga"]
  spec.email         = ["yuta@culturescience.io"]
  spec.summary       = %q{OmniAuth provider for Microsoft Office365 Admin Consent}
  spec.description   = %q{OmniAuth provider for Microsoft Office365 Admin Consent}
  spec.homepage      = "https://github.com/Culture-Science/microsoft-office365-admin-consent"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 3.1.3'

  spec.add_runtime_dependency "omniauth"
  spec.add_runtime_dependency "omniauth-oauth2"

  spec.add_development_dependency "bundler", ">= 1.17"
  spec.add_development_dependency "rake", ">= 13.0"
  spec.add_development_dependency "rspec", ">= 3.4.0"
  spec.add_development_dependency "pry", ">= 0.10.3"
end
