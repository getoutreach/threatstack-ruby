require 'threatstack/serializable'
require 'threatstack/entities/agent'
require 'threatstack/entities/alert'
require 'threatstack/entities/cve'
require 'threatstack/entities/generic_object'
require 'threatstack/entities/ruleset'
require 'threatstack/entities/rule'

module Threatstack
  class InvalidEntity < StandardError; end
  class Response
    attr_reader :entity, :raw, :client
    include Serializable

    def agents
      raise InvalidEntity unless entity == :agent
      raw.map{ |a| Agent.new(a, client) }
    end

    def alerts
      raise InvalidEntity unless entity == :alert
      raw.map{ |a| Alert.new(a, client) }
    end

    def cves
      raise InvalidEntity unless entity == :cve
      raw.map{ |a| Cve.new(a, client) }
    end

    def rulesets
      raise InvalidEntity unless entity == :ruleset
      raw.map{ |r| Ruleset.new(r, client) }
    end

    def rules
      raise InvalidEntity unless entity == :rule
      raw.map{ |r| Rule.new(r, client) }
    end

    def list
      raw.map { |g| GenericObject.new(g, client) }
    end
  end
end
