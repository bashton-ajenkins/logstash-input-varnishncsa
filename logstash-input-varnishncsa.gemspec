Gem::Specification.new do |s|

  s.name            = 'logstash-input-varnishncsa'
  s.version         = '2.0.5'
  s.licenses        = ['Apache License (2.0)']
  s.summary         = "Read from varnish cache's shared memory log and return all value in a logstash field (rewrite of varnishlog in ruby)"
  s.description     = "This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program"
  s.authors         = ["hans moulron"]
  s.email           = 'hans.moulron@francetv.fr'
  s.homepage        = "https://github.com/francetv/logstash-input-varnishncsa"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','Gemfile','LICENSE']

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "input" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core", ">= 2.1.0", "< 3.0.0"

  s.add_runtime_dependency 'varnish-wrapper'

  s.add_development_dependency 'logstash-devutils'
end

