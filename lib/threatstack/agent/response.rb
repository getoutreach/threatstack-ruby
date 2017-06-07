require 'threatstack/agent/agent'

module Threatstack
  module Agent
    class Response
      attr_reader :raw
      def initialize(raw)
        @raw = raw
      end

      def agents
        raw.map{ |a| Agent.new(a) }
      end
    end
  end
end
