require 'threatstack/serializable'

module Threatstack
  class UserIdentity
    include Serializable
    attributes :user_name, :session_context, :invoked_by, :account_id, :access_key_id, :principal_id

    def user_name
      raw['userName']
    end

    def session_context
      raw['sessionContext']
    end

    def invoked_by
      raw['invokedBy']
    end

    def account_id
      raw['accountId']
    end

    def access_key_id
      raw['accessKeyId']
    end

    def principal_id
      raw['principalId']
    end
  end
end
