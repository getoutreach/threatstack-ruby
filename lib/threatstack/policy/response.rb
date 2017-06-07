require 'threatstack/policy/policy'
require 'threatstack/serializable'

module Threatstack
  module Policy
    class Response
      include Serializable
      attributes :policies

      def policies
        raw.map{ |a| Policy.new(a) }
      end
    end
  end
end
