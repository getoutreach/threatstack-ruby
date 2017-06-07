require 'threatstack/alert/alert'
require 'threatstack/serializable'

module Threatstack
  module Alert
    class Response
      include Serializable
      attributes :alerts
      
      def alerts
        raw.map{ |a| Alert.new(a) }
      end
    end
  end
end
