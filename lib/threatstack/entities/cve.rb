require 'threatstack/serializable'

module Threatstack
  class Cve
    include Serializable
    attributes :cve_number, :reported_package, :system_package, :vector_type,
      :affected_servers, :is_suppressed, :severity
  end
end
