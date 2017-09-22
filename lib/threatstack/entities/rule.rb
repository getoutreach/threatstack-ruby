require 'threatstack/serializable'

module Threatstack
  class Rule
    include Serializable
    attributes :id, :ruleset_id, :name, :type, :severity_of_alerts, :alert_description,
      :aggregate_fields, :filter, :frequency, :threshold, :suppressions, :ignore_files,
      :file_integrity_paths, :events_to_monitor

    def ruleset
      client.ruleset(ruleset_id)
    end
  end
end
