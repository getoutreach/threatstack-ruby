require 'open-uri'
require 'httparty'
require 'threatstack/response'
require 'threatstack/entities/agent'
require 'threatstack/entities/alert'
require 'threatstack/entities/ruleset'
require 'threatstack/entities/rule'


module Threatstack
  class ThreatstackError < StandardError; end

  class Client
    THREATSTACK_API = 'https://api.threatstack.com'.freeze
    attr_reader :token, :org_id, :api_version, :last_pagination_token

    def initialize(token, organization_id: nil, api_version: 'v2')
      @api_version = api_version
      @token = token
      @org_id = organization_id
      if api_version == 'v1'
        raise ThreatstackError, "This version of threatstack-ruby does not support Threatstack API v1"
      end
    end

    ### ALERTS ###

    def agents(params = {})
      response = do_request(:get, 'agents', params)
      Response.new(response['agents'], self, entity: :agent).agents
    end

    def agent(agent_id, params = {})
      raise ThreatstackError, "Must specify agent id" unless agent_id
      response = do_request(:get, "agents/#{agent_id}", params)
      Agent.new(response, self)
    end

    ### ALERTS ###
    def alerts(params = {})
      response = do_request(:get, 'alerts', params)
      Response.new(response['alerts'], self, entity: :alert).alerts
    end

    def dismissed_alerts(params = {})
      response = do_request(:get, 'alerts/dismissed', params)
      Response.new(response['alerts'], self, entity: :alert).alerts
    end

    def alert(alert_id, params = {})
      raise ThreatstackError, "Must specify alert id" unless alert_id
      response = do_request(:get, "alerts/#{alert_id}", params)
      Alert.new(response, self)
    end

    def severity_counts(params = {})
      response = do_request(:get, "alerts/severity-counts", params)
      Response.new(response['severityCounts'], self, entity: :severity_count).list
    end

    def event(alert_id, event_id, params = {})
      response = do_request(:get, "alerts/#{alert_id}/events/#{event_id}", params)
      GenericObject.new(response['details'], self, entity: :event)
    end

    ### CVEs ###

    def vulnerabilities(params = {})
      uri = "vulnerabilities"
      uri += "/suppressed" if params[:suppressed]
      response = do_request(:get, uri, params)
      Response.new(response['cves'], self, entity: :cve).cves
    end

    def vulnerability(vuln_id, params = {})
      raise ThreatstackError, "Must specify vulnerability id" unless vuln_id
      response = do_request(:get, "vulnerabilities/#{vuln_id}", params)
      Cve.new(response, self)
    end

    def package_vulnerabilities(package, params = {})
      raise ThreatstackError, "Must specify package" unless package
      uri = "vulnerabilities/package/#{package}"
      uri += "/suppressed" if params[:suppressed]
      response = do_request(:get, uri, params)
      Response.new(response['packages'], self, entity: :package).list
    end

    def server_vulnerabilities(server, params = {})
      raise ThreatstackError, "Must specify server" unless server
      uri = "vulnerabilities/server/#{server}"
      uri += "/suppressed" if params[:suppressed]
      response = do_request(:get, uri, params)
      response['cves']
    end

    def cves_by_agent(agent, params = {})
      raise ThreatstackError, "Must specify agent" unless agent
      uri = "vulnerabilities/agent/#{agent}"
      uri += "/suppressed" if params[:suppressed]
      response = do_request(:get, uri, params)
      response['cves']
    end

    def vulnerability_suppressions(params = {})
      response = do_request(:get, "vulnerabilities/suppressions", params)
      Response.new(response['suppressions'], self, entity: :suppression).list
    end

    ### Rulesets ###

    def rulesets(params = {})
      response = do_request(:get, 'rulesets', params)
      Response.new(response['rulesets'], self, entity: :ruleset).rulesets
    end

    def ruleset(ruleset_id, params = {})
      raise ThreatstackError, "Must specify ruleset id" unless ruleset_id
      response = do_request(:get, "rulesets/#{ruleset_id}", params)
      Ruleset.new(response, self)
    end

    ### Rules ###

    def rules(ruleset_id, params = {})
      response = do_request(:get, "rulesets/#{ruleset_id}/rules", params)
      Response.new(response['rules'], self, entity: :rule).rules
    end

    def rule(ruleset_id, rule_id, params = {})
      raise ThreatstackError, "Must specify ruleset id and rule id" unless ruleset_id && rule_id
      response = do_request(:get, "rulesets/#{ruleset_id}/rules/#{rule_id}", params)
      Rule.new(response, self)
    end

    ### Servers ###

    def servers(monitored = true, params = {})
      uri = "servers"
      uri += "/non-monitored" unless monitored
      response = do_request(:get, uri, params)
      Response.new(response['servers'], self, entity: :server).list
    end

    private

    def do_request(method, path, params = {})
      headers = { "Authorization" => token, "Organization-Id" => org_id }
      response = HTTParty.public_send(method, build_uri(path, params), headers: headers).parsed_response
      if response.instance_of?(Hash) && response['status'] == 'error'
        raise ThreatstackError, response['message']
      end
      @last_pagination_token = response['token']
      response
    end

    def build_uri(path, params = {})
      params[:from] = params[:from].utc if params[:from]
      params[:until] = params[:until].utc if params[:until]
      params[:fields] = params[:fields].join(',') if params[:fields]&.is_a?(Array)

      query = params.each_pair.map { |k, v| "#{k}=#{v}" }.join('&')
      uri = "#{THREATSTACK_API}/#{api_version}/#{path}"
      uri += "?#{URI::encode(query)}" if params.any?
      uri
    end
  end
end
