require 'threatstack/entities/user_identity'
require 'threatstack/serializable'

module Threatstack
  class Event
    include Serializable
    attributes :user_identity

    def user_identity
      UserIdentity.new(raw['userIdentity'])
    end
  end
end
