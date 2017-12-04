require 'threatstack/serializable'

module Threatstack
  class Agent
    include Serializable
    attributes :id, :instance_id, :status, :activated_at, :last_reported_at,
      :version, :name, :description, :hostname, :tags, :agent_type, :kernel

    def tags
      raw['tags'].map{ |t| Tag.new(t) }
    end
  end
end
