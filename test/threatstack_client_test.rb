require 'test_helper'

describe Threatstack::Client do
  let(:client) { Threatstack::Client.new("fake_token") }
  let(:payload_singular) { {'foo' => 'bar'} }
  let(:payload_plural) { [payload_singular] }

  describe "when entity is alert" do
    it 'returns an Alert object' do
      HTTParty.stub :get, payload_singular do
        a = client.alert(1)
        a.class.name.must_equal "Threatstack::Alert"
        a.foo.must_equal "bar"
      end
    end

    it 'returns an Alert object in an array' do
      HTTParty.stub :get, payload_plural do
        a = client.alerts.first
        a.class.name.must_equal "Threatstack::Alert"
        a.foo.must_equal "bar"
      end
    end
  end

  describe "when entity is agent" do
    it 'returns an Agent object' do
      HTTParty.stub :get, payload_singular do
        a = client.agent(1)
        a.class.name.must_equal "Threatstack::Agent"
        a.foo.must_equal "bar"
      end
    end

    it 'returns an Agent object in an array' do
      HTTParty.stub :get, payload_plural do
        a = client.agents.first
        a.class.name.must_equal "Threatstack::Agent"
        a.foo.must_equal "bar"
      end
    end
  end

  describe "when entity is log" do
    it 'returns an Log object in an array' do
      HTTParty.stub :get, payload_plural do
        a = client.logs.first
        a.class.name.must_equal "Threatstack::Log"
        a.foo.must_equal "bar"
      end
    end
  end

  describe "when entity is organization" do
   it 'returns an Organization object in an array' do
      HTTParty.stub :get, payload_plural do
        a = client.organizations.first
        a.class.name.must_equal "Threatstack::Organization"
        a.foo.must_equal "bar"
      end
    end
  end

  describe "when entity is policy" do
    it 'returns an Policy object' do
      HTTParty.stub :get, payload_singular do
        a = client.policy(1)
        a.class.name.must_equal "Threatstack::Policy"
        a.foo.must_equal "bar"
      end
    end

    it 'returns an Policy object in an array' do
      HTTParty.stub :get, payload_plural do
        a = client.policies.first
        a.class.name.must_equal "Threatstack::Policy"
        a.foo.must_equal "bar"
      end
    end
  end
end
