require 'test_helper'

describe Threatstack::Client do
  let(:client) { Threatstack::Client.new("fake_token", '', '') }
  let(:key) { nil }
  let(:payload_singular) { {'foo' => 'bar'} }
  let(:payload_plural) { {key => [payload_singular]} }

  describe "when entity is alert" do
    let(:key) { 'alerts' }
    it 'returns an Alert object' do
      client.stub :do_request, payload_singular do
        a = client.alert("1")
        a.class.name.must_equal "Threatstack::Alert"
        a.foo.must_equal "bar"
      end
    end

    it 'returns an Alert object in an array' do
      alert1 = {
        'id': 'foo'
      }

      client.stub :do_request, payload_plural do
        a = client.alerts('active').first
        a.class.name.must_equal "Threatstack::Alert"
        a.foo.must_equal "bar"

        b = client.alerts('dismissed').first
        b.class.name.must_equal "Threatstack::Alert"
        b.foo.must_equal "bar"
      end

      client.stub :do_request, { 'severityCounts' => [{'foo' => 'bar'}]} do
        a = client.severity_counts.first
        a.class.name.must_equal 'Threatstack::GenericObject'
        a.foo.must_equal 'bar'
      end

      client.stub :do_request, { 'events' => [{'foo' => 'bar'}]} do
        a = client.events('a').first
        a.class.name.must_equal 'Threatstack::GenericObject'
        a.foo.must_equal 'bar'
      end
    end
  end

  describe "when entity is agent" do
    let(:key) { 'agents' }
    it 'returns an Agent object' do
      client.stub :do_request, payload_singular do
        a = client.agent("1")
        a.class.name.must_equal "Threatstack::Agent"
        a.foo.must_equal "bar"
      end
    end

    it 'returns an Agent object in an array' do
      client.stub :do_request, payload_plural do
        a = client.agents('online').first
        a.class.name.must_equal "Threatstack::Agent"
        a.foo.must_equal "bar"
      end
    end
  end

  describe 'when entity is vulnerability' do
    let(:key) { 'cves'}

    stub_response = {
      'cveNumber' => '1', 
      'reportedPackage' => 'package',
      'systemPacage' => 'system',
      'vectorType' => 'network',
      'isSuppressed' => true,
      'severity' => 'high'
    }

    it 'returns a Cve object in an array' do
      client.stub :do_request, { 'cves' => [stub_response]} do
        a = client.vulnerabilities.first
        a.class.name.must_equal 'Threatstack::Cve'
        a.cve_number.must_equal '1'
      end
    end

    it 'returns generic package objects' do
      client.stub :do_request, { 'packages' => [{'foo' => 'bar'}]} do
        a = client.package_vulnerabilities('package').first
        a.class.name.must_equal 'Threatstack::GenericObject'
        a.foo.must_equal 'bar'
      end
    end

    it 'returns a list of affected servers' do
      client.stub :do_request, {'servers' => [{'agent_id' => 1, 'hostname' => 'host'}] } do
        a = client.affected_servers('server').first
        expected = {'agent_id' => 1, 'hostname' => 'host'}
        a.must_equal expected
      end
    end

    it 'returns a list of suppressions' do
      client.stub :do_request, {'suppressions' => [{ 'foo' => 'bar'}]} do
        a = client.vulnerability_suppressions.first
        a.foo.must_equal 'bar'
      end
    end
  end

  describe 'when entity is a ruleset' do
    let(:key) { 'rulesets' }
    it 'returns a list of rulesets' do
      client.stub :do_request, payload_plural do
        a = client.rulesets.first
        a.foo.must_equal 'bar'
        a.class.name.must_equal 'Threatstack::Ruleset'
      end
    end

    it 'returns a ruleset' do
      client.stub :do_request, payload_singular do
        a = client.ruleset('1')
        a.foo.must_equal 'bar'
        a.class.name.must_equal 'Threatstack::Ruleset'
      end
    end
  end

  describe 'when entity is a rule' do
    let(:key) { 'rules' }
    it 'returns a rule from a ruleset' do
      client.stub :do_request, payload_plural do
        a = client.rules('1').first
        a.foo.must_equal 'bar'
        a.class.name.must_equal 'Threatstack::Rule'
      end

      client.stub :do_request, payload_singular do
        a = client.rule('1', '2')
        a.foo.must_equal 'bar'
        a.class.name.must_equal 'Threatstack::Rule'
      end
    end
  end

  describe 'when entity is a server' do
    let(:key) { 'servers' }
    it 'returns a list of servers' do
      client.stub :do_request, payload_plural do
        a = client.instances.first
        a.foo.must_equal 'bar'
        a.class.name.must_equal 'Threatstack::GenericObject'
      end
    end
  end
end
