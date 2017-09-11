require 'threatstack/entities/agent'
require 'threatstack/entities/alert'
require 'threatstack/entities/log'
require 'threatstack/entities/organization'
require 'threatstack/entities/policy'

module Threatstack
  class InvalidEntity < StandardError; end
  class Response
    attr_reader :entity, :raw
    def initialize(entity, raw)
      @raw = raw
      @entity = entity
    end

    def agents
      raise InvalidEntity unless entity == :agent
      raw.map{ |a| Agent.new(a) }
    end

    def alerts
      raise InvalidEntity unless entity == :alert
      raw.map{ |a| Alert.new(a) }
    end

    def logs
      raise InvalidEntity unless entity == :log
      raw.map{ |a| Log.new(a) }
    end

    def organizations
      raise InvalidEntity unless entity == :organization
      raw.map{ |a| Organization.new(a) }
    end

    def policies
      raise InvalidEntity unless entity == :policy
      raw.map{ |a| Policy.new(a) }
    end
  end
end
