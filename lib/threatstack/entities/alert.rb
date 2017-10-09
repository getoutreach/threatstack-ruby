require 'threatstack/serializable'

module Threatstack
  class Alert
    include Serializable
    attributes :id, :title, :type, :created_at, :event_count, :is_dismissed, :dismissed_at,
      :dismissed_reason, :dismissed_reason_text, :dismissed_by, :severity, :agent_id,
      :rule_id, :ruleset_id, :event_ids

    def rule
      client.rule(ruleset_id, rule_id)
    end

    def agent
      client.agent(agent_id)
    end

    def ruleset
      client.ruleset(ruleset_id)
    end

    def events
      event_ids&.map{ |event_id| client.event(id, event_id)}
    end
  end
end
