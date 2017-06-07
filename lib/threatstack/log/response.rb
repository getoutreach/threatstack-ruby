require 'threatstack/log/log'

module Threatstack
  module Log
    class Response
      include Serializable
      attributes :logs

      def logs
        raw.map{ |a| Log.new(a) }
      end
    end
  end
end
