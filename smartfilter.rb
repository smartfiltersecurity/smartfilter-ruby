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

  # Endpoint: /xss/detect
  def detect(input, whitelist)
    begin
      return detect!(input, whitelist)
    rescue => e
      return nil
    end
  end

  def detect!(input, whitelist)
    options = {:api_key => @key, :input => input, :whitelist_id => whitelist}
    response = HTTParty.post("#{@base}/xss/detect", :query => options)
    return JSON.parse(response.body) if response.code == 200
    raise SmartFilterBadInputParameter.new if response.code == 400
    raise SmartFilterBadAPIKey.new if response.code == 403
    raise SmartFilterRequestTooLarge.new if response.code == 413
    raise SmartFilterInternalError.new if response.code == 500
    raise SmartFilterAccountQuotaExceeded.new if response.code == 507
    Array.new
  end

  # Endpoint: /xss/filter
  def filter(input, whitelist)
    begin
      return filter!(input, whitelist)
    rescue => e
      return nil
    end
  end

  def filter!(input, whitelist)
    options = {:api_key => @key, :input => input, :whitelist_id => whitelist}
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
