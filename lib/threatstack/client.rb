require 'open-uri'
require 'httparty'
require 'threatstack/response'
require 'threatstack/entities/agent'
require 'threatstack/entities/alert'
require 'threatstack/entities/log'
require 'threatstack/entities/organization'
require 'threatstack/entities/policy'

module Threatstack
  class ThreatstackError < StandardError; end

  class Client
    THREATSTACK_API = 'https://app.threatstack.com/api'.freeze

    attr_reader :token, :org_id, :api_version

    def initialize(token, api_version = 'v1')
      @api_version = api_version
      @token = token
    end

    def agents(params = {})
      response = do_request(:get, 'agents', params)
      Response.new(:agent, response).agents
    end

    def agent(agent_id, params = {})
      raise ThreatstackError, "Must specify agent id" unless agent_id
      response = do_request(:get, "agents/#{agent_id}", params)
      Agent.new(response)
    end

    def alerts(params = {})
      response = do_request(:get, 'alerts', params)
      Response.new(:alert, response).alerts
    end

    def alert(alert_id, params = {})
      raise ThreatstackError, "Must specify alert id" unless alert_id
      response = do_request(:get, "alerts/#{alert_id}", params)
      Alert.new(response)
    end

    def policies(params = {})
      response = do_request(:get, 'policies', params)
      Response.new(:policy, response).policies
    end

    def policy(policy_id, params = {})
      raise ThreatstackError, "Must specify policy id" unless policy_id
      response = do_request(:get, "policies/#{policy_id}", params)
      Policy.new(response)
    end

    def organizations(params = {})
      response = do_request(:get, 'organizations', params)
      Response.new(:organization, response).organizations
    end

    def logs(params = {})
      response = do_request(:get, 'logs', params)
      Response.new(:log, response).logs
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
      uri = "#{THREATSTACK_API}/#{api_version}/#{path}"
      uri += "?#{URI::encode(query)}" if params.any?
      uri
    end

  end
end
