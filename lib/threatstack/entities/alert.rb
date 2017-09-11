require 'threatstack/entities/event'
require 'threatstack/entities/rule'
require 'threatstack/serializable'

module Threatstack
  class Alert
    include Serializable
    attributes :latest_events, :rule

    def latest_events
      raw['latest_events'].map do |event|
        Event.new(event)
      end
    end

    def rule
      Rule.new(raw['rule'])
    end
  end
end
