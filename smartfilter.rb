require 'rubygems'
require 'httparty'
require 'json'

class SmartFilterNetworkException < Exception; end
class SmartFilterBadInputParameter < Exception; end
class SmartFilterBadAPIKey < Exception; end
class SmartFilterRequestTooLarge < Exception; end
class SmartFilterInternalError < Exception; end
class SmartFilterAccountQuotaExceeded < Exception; end

class SmartFilter
  attr_accessor :key, :base

  def initialize(key)
    @key = key
    @base = 'http://api.prevoty.com/1'
  end

  # Endpoint: /key/verify
  def verify
    begin
      return verify!
    rescue => e
      return nil
    end
  end

  def verify!
    options = {:api_key => @key}
    response = HTTParty.get("#{@base}/key/verify", :query => options)
    return true if response.code == 200
    raise SmartFilterBadInputParameter.new if response.code == 400
    raise SmartFilterBadAPIKey.new if response.code == 403
    raise SmartFilterInternalError.new if response.code == 500
    false
  end

  # Endpoint: /key/info
  def info 
    begin
      return info!
    rescue => e
      return nil
    end
  end

  def info!
    options = {:api_key => @key}
    response = HTTParty.get("#{@base}/key/info", :query => options)
    return JSON.parse(response.body) if response.code == 200
    raise SmartFilterBadInputParameter.new if response.code == 400
    raise SmartFilterBadAPIKey.new if response.code == 403
    raise SmartFilterInternalError.new if response.code == 500
    Array.new
  end

  # Endpoint: /rule/verify
  def verify_rule(rule_key)
    begin
      return verify_rule!(rule_key)
    rescue => e
      return nil
    end
  end

  def verify_rule!(rule_key)
    options = {:api_key => @key, :rule_key => rule_key}
    response = HTTParty.get("#{@base}/rule/verify", :query => options)
    return true if response.code == 200
    raise SmartFilterBadInputParameter.new if response.code == 400
    raise SmartFilterBadAPIKey.new if response.code == 403
    raise SmartFilterInternalError.new if response.code == 500
    false
  end

  # Endpoint: /xss/filter
  def filter(input, rule_key)
    begin
      return filter!(input, rule_key)
    rescue => e
      return nil
    end
  end

  def filter!(input, rule_key)
    puts @key
    puts rule_key
    options = {:api_key => @key, :input => input, :rule_key => rule_key}
    response = HTTParty.post("#{@base}/xss/filter", :query => options)
    return JSON.parse(response.body) if response.code == 200
    raise SmartFilterBadInputParameter.new if response.code == 400
    raise SmartFilterBadAPIKey.new if response.code == 403
    raise SmartFilterRequestTooLarge.new if response.code == 413
    raise SmartFilterInternalError.new if response.code == 500
    raise SmartFilterAccountQuotaExceeded.new if response.code == 507
    Array.new
  end
end
