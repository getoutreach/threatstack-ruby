require 'open-uri'
require 'httparty'
require 'hawk'
require 'threatstack/response'
require 'threatstack/entities/agent'
require 'threatstack/entities/alert'
require 'threatstack/entities/ruleset'
require 'threatstack/entities/rule'

module Threatstack
  class ThreatstackError < StandardError; end

  class Client
    THREATSTACK_API = 'api.threatstack.com'.freeze
    PORT = 443
    attr_reader :org_id, :user_id, :api_key, :api_version, :last_pagination_token

    def initialize(organization_id, user_id, api_key, api_version: 'v2')
      @org_id = organization_id
      @user_id = user_id
      @api_key = api_key
      @api_version = api_version
      if api_version == 'v1'
        raise ThreatstackError, "This version of threatstack-ruby does not support Threatstack API v1"
      end
    end

    ### AGENTS ###
    def agents(status, params = {})
      if !valid_agent_status?(status)
        raise ThreatstackError, "Must specify status with value of 'online' or 'offline'"
      end
      params[:status] = status
      response = do_request(:get, 'agents', params)
      Response.new(response['agents'], self, entity: :agent).agents
    end

    def agent(agent_id)
      raise ThreatstackError, "Must specify agent id" unless agent_id
      response = do_request(:get, "agents/#{agent_id}")
      Agent.new(response, self)
    end

    ### ALERTS ###
    def alerts(status, params = {})
      if !valid_alert_status?(status)
        raise ThreatstackError, "Must specify status with value of 'active' or 'dismissed'"
      end
      params[:status] = status
      response = do_request(:get, 'alerts', params)
      Response.new(response['alerts'], self, entity: :alert).alerts
    end

    def alert(alert_id, params = {})
      raise ThreatstackError, "Must specify alert id" unless alert_id
      response = do_request(:get, "alerts/#{alert_id}")
      Alert.new(response, self)
    end

    def severity_counts(params = {})
      response = do_request(:get, "alerts/severity-counts", params)
      Response.new(response['severityCounts'], self, entity: :severity_count).list
    end

    def events(alert_id)
      response = do_request(:get, "alerts/#{alert_id}/events")
      Response.new(response['events'], self, entity: :events).list
    end

    ### CVEs ###

    def vulnerabilities(params = {})
      uri = "vulnerabilities"
      response = do_request(:get, uri, params)
      Response.new(response['cves'], self, entity: :cve).cves
    end

    def package_vulnerabilities(package, params = {})
      raise ThreatstackError, "Must specify package" unless package
      uri = "vulnerabilities/package/#{package}"
      response = do_request(:get, uri, params)
      Response.new(response['packages'], self, entity: :package).list
    end

    def affected_servers(cve)
      raise ThreatstackError, "Must specify a cve" unless cve
      uri = "vulnerabilities/#{cve}/servers"
      response = do_request(:get, uri)
      response['servers']
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

    def ruleset(ruleset_id)
      raise ThreatstackError, "Must specify ruleset id" unless ruleset_id
      response = do_request(:get, "rulesets/#{ruleset_id}")
      Ruleset.new(response, self)
    end

    def agents_for_ruleset(ruleset_id)
      raise ThreatstackError, "Must specify ruleset id" unless ruleset_id
      response = do_request(:get, "rulesets/#{ruleset_id}")
      Response.new(response['agents'], self, entity: :agent).agents
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

    ### EC2 Instances ###

    def instances(monitored = nil)
      uri = "aws/ec2"
      params = monitored ? { isMonitored: monitored } : {}
      response = do_request(:get, uri, params)
      Response.new(response['servers'], self, entity: :server).list
    end

    private

    def valid_agent_status?(status)
      status && (status == 'online' || status == 'offline')
    end

    def valid_alert_status?(status)
      status && (status == 'active' || status == 'dismissed')
    end

    def do_request(method, path, params = {})
      convert_dates(params)
      uri = build_uri(path, params, "https://#{THREATSTACK_API}:#{PORT}")
      auth_info_uri = build_uri(path, params)
      auth_token = calculate_auth_info(method, auth_info_uri)
      headers = { "Authorization" => Hawk::Client.build_authorization_header(auth_token) }

      response = HTTParty.public_send(method, uri, headers: headers)
      if !response.success?
        raise ThreatstackError, "Response returned with status #{response.code} with message #{response.message}."
      end

      response_auth_header = response.headers['Server-Authorization']

      auth_token[:payload] = response.body
      auth_token[:content_type] = "application/json"

      auth_result = Hawk::Client.authenticate(response_auth_header, auth_token)
      if auth_result['id'] != auth_token[:credentials]['id']
        raise ThreatstackError, "Response was not authentic"
      end

      @last_pagination_token = response['token']
      response
    end

    def convert_dates(params)
      params[:from] = params[:from].utc.iso8601 if params[:from]
      params[:until] = params[:until].utc.iso8601 if params[:until]
      params[:fields] = params[:fields].join(',') if params[:fields]&.is_a?(Array)
    end

    def build_uri(path, params = {}, root = '')
      query = params.each_pair.map { |k, v| "#{k}=#{v}" }.join('&')
      uri = "#{root}/#{api_version}/#{path}"
      uri += "?#{URI::encode(query)}" if params.any?
      uri
    end

    def calculate_auth_info(method, request_uri)
      ts = Time.now.to_i
      nonce = SecureRandom.hex(4)
      credentials = { :id => @user_id, :key => @api_key, :algorithm => 'sha256' }
      {
        :credentials => credentials,
        :method => method.to_s.upcase,
        :request_uri => request_uri,
        :host => THREATSTACK_API,
        :ext => @org_id,
        :port => PORT,
        :nonce => nonce,
        :ts => ts
      }
    end
  end
end
