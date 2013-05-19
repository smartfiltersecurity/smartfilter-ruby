require 'rubygems'
require 'awesome_print'
require 'smartfilter'

api_key = 'api key goes here'
rule_key = 'rule key goes here'
input = 'the <script>alert("quick brown fox");</script> jumps over the lazy dog & mouse'

smartfilter = SmartFilter.new(api_key)

begin
  # verify (returns a boolean)
  ap smartfilter.verify!
  # info (returns a hash with the goodies)
  ap smartfilter.info!
  # verify_rule (returns a hash with the goodies)
  ap smartfilter.verify_rule!(rule_key)
  # filter (returns a hash with the goodies)
  ap smartfilter.filter!(input, rule_key)
rescue SmartFilterNetworkException => e
  puts 'Network connectivity issue'
rescue SmartFilterBadInputParameter => e
  puts 'Bad input parameter exception'
rescue SmartFilterBadAPIKey => e
  puts 'Bad API key'
rescue SmartFilterRequestTooLarge => e
  puts 'Request too large'
rescue SmartFilterInternalError => e
  puts 'Internal Prevoty error'
rescue SmartFilterAccountQuotaExceeded => e
  puts 'Account quota exceeded'
end