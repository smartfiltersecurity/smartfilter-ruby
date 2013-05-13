require 'rubygems'
require 'awesome_print'
require 'smartfilter'

key = 'key goes here'
whitelist = 'whitelist goes here'
input = 'the <script>alert("quick brown fox");</script> jumps over the lazy dog'

smartfilter = SmartFilter.new(key)

begin
  # Verify (returns a boolean)
  ap smartfilter.verify!
  # Info (returns a hash with the goodies)
  ap smartfilter.info!
  # Detect (returns a hash with the goodies)
  ap smartfilter.detect!(input, whitelist)
  # Filter (returns a hash with the goodies)
  ap smartfilter.filter!(input, whitelist)
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