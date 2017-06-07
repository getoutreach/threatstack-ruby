require 'open-uri'
require 'httparty'
require 'threatstack/alert/response'
require 'threatstack/alert/alert'
require 'threatstack/agent/response'
require 'threatstack/agent/agent'
require 'threatstack/policy/response'
require 'threatstack/policy/policy'
require 'threatstack/organization/response'
require 'threatstack/log/response'

module Threatstack
  class ThreatstackError < StandardError; end

  class Client
    THREATSTACK_API = 'https://app.threatstack.com/api/v1'

    attr_reader :token, :org_id

    def initialize(token)
      @token = token
    end

    def alerts(params = {})
      response = do_request(:get, 'alerts', params)
      Alert::Response.new(response).alerts
    end

    def alert(alert_id, params = {})
      raise ThreatstackError, "Must specify alert id" unless alert_id
      response = do_request(:get, "alerts/#{alert_id}", params)
      Alert::Alert.new(response)
    end

    def agents(params = {})
      response = do_request(:get, 'agents', params)
      Agent::Response.new(response).agents
    end

    def agent(agent_id, params = {})
      raise ThreatstackError, "Must specify agent id" unless agent_id
      response = do_request(:get, "agents/#{agent_id}", params)
      Agent::Agent.new(response)
    end

    def policies(params = {})
      response = do_request(:get, 'policies', params)
      Policy::Response.new(response).policies
    end

    def policy(policy_id, params = {})
      raise ThreatstackError, "Must specify policy id" unless policy_id
      response = do_request(:get, "policies/#{policy_id}", params)
      Policy::Policy.new(response)
    end

    def organizations(params = {})
      response = do_request(:get, 'organizations', params)
      Organization::Response.new(response).organizations
    end

    def logs(params = {})
      response = do_request(:get, 'logs', params)
      Log::Response.new(response).logs
    end

    def search(query, params = {})
      logs(params.merge(q: query))
    end

    private

    def do_request(method, path, params = {})
      response = HTTParty.public_send(method, build_uri(path, params), headers: { "Authorization" => token })
      if response.instance_of?(Hash) && response['status'] == 'error'
        raise ThreatstackError, response['message']
      end
      response
    end

    def build_uri(path, params = {})
      params[:start] = params[:start].utc if params[:start]
      params[:end] = params[:end].utc if params[:end]
      params[:fields] = params[:fields].join(',') if params[:fields]&.is_a?(Array)

      query = params.each_pair.map { |k, v| "#{k}=#{v}" }.join('&')
      uri = "#{THREATSTACK_API}/#{path}"
      uri += "?#{URI::encode(query)}" if params.any?
      uri
    end

  end
end
