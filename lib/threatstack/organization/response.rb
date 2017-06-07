require 'threatstack/organization/organization'
require 'threatstack/serializable'

module Threatstack
  module Organization
    class Response
      include Serializable
      attributes :organizations

      def organizations
        raw.map{ |a| Organization.new(a) }
      end
    end
  end
end
