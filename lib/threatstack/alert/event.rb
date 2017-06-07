require 'threatstack/alert/user_identity'
require 'threatstack/serializable'

module Threatstack
  module Alert
    class Event
      include Serializable
      attributes :user_identity

      def user_identity
        UserIdentity.new(raw['userIdentity'])
      end
    end
  end
end
