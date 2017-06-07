require 'threatstack/alert/event'
require 'threatstack/alert/rule'
require 'threatstack/serializable'

module Threatstack
  module Alert
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
end
