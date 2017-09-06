require 'threatstack/entities/rule'

module Threatstack
  class Policy
    include Serializable
    attributes :rules

    def rules
      raw['alert_policy'].map{ |r| Rule.new(r) }
    end
  end
end
