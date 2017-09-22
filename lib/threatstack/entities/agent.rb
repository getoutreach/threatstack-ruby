require 'threatstack/serializable'

module Threatstack
  class Agent
    include Serializable
    attributes :id, :instance_id, :status, :activated_at, :last_reported_at,
      :version, :name, :description, :hostname, :tags, :agent_type

    def tags
      raw['tags'].map{ |t| Tag.new(t) }
    end

    def ruleset_ids
      raw['rulesets']
    end

    def rulesets
      ruleset_ids.each { |id| client.ruleset(id) }
    end
  end
end
