require 'threatstack/policy/policy'
require 'threatstack/alert/rule'

module Threatstack
  module Policy
    class Policy
      include Serializable
      attributes :rules

      def rules
        raw['alert_policy'].map{ |r| Threatstack::Alert::Rule.new(r) }
      end
    end
  end
end
