require 'threatstack/serializable'
module Threatstack
  module Alert
    class Rule
      include Serializable
      attributes :original_rule

      def original_rule
        Rule.new(raw['original_rule'])
      end
    end
  end
end
