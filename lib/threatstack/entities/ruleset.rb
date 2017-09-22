require 'threatstack/serializable'

module Threatstack
  class Ruleset
    include Serializable
    attributes :id, :rule_ids, :name, :created_at, :updated_at, :description, :agents

    def rules
      client.rules(id)
    end
  end
end
