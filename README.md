# Threatstack

Threatstack is a tool for monitoring your infrastructure and hosts for malicious or suspicious activity. They have this handy little API that I decided to write a Ruby wrapper for. This is a very thin wrapper that only transforms keys for the purpose of changing them to snake_case like the rest of the ruby world. Otherwise, this maps very closely to the API docs found here: https://app.threatstack.com/api/docs

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'threatstack'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install threatstack

## Usage

You can access all attributes on responses thanks to the method_missing function in Ruby. We only munged the attributes that don't correspond to snake_case. If you want to see a list of all available attributes for a serializable response object, simply do something like this:

```
client = Threatstack::Client.new(API_TOKEN)
client.policies.first.attrs
=> [:rules,
 :id,
 :name,
 :created_at,
 :updated_at,
 :enabled,
 :agent_count,
 :alert_rule_count,
 :description,
 :organization_id,
 :alert_policy_id,
 :alert_policy,
 :file_integrity_rules]
 ```

### Alerts

```
client = Threatstack::Client.new(API_TOKEN)
## All these are optional url params. See the Threatstack API Docs
alert = client.alerts(start: 3.days.ago, end: Time.now, count: 5).last
=> #<Threatstack::Alert::Alert:0x007fde0b01cbd8
 @raw=
  {"created_at"=>1496850520000,
   "expires_at"=>1496936920000,
   "last_updated_at"=>"2017-06-07T16:03:56.270Z",
   "count"=>4,
   "title"=>"CloudTrail Activity : EC2 Service Policy Changes : CreateVolume by ryan_canty",
   ...
event = alert.latest_events.last
=> <Threatstack::Alert::Event:0x007fde0ca08420
 @raw=
  {"user"=>"ryan_canty",
   "userType"=>"IAMUser",
   ...
user_that_caused_the_event = event.user_identity.arn
=> "arn:aws:iam::1234567890:user/ryan_canty"

```

You can also limit the response if that's important to you:

```
client.alerts(fields: ['title', 'alerts'])
=> [#<Threatstack::Alert::Alert:0x007fd61348c768
  @raw={"title"=>"CloudTrail Activity (IAM Policy Changes) : CreateAccessKey by ryan_canty", "severity"=>2}>]
```

You can also get a single alert by id using:

```
client.alert('1234567890')
```

### Agents

```
client.agents
=>  [#<Threatstack::Agent::Agent:0x007fa262b0b2e0 @raw={...}> ]
client.agent
=>  #<Threatstack::Agent::Agent:0x007fa262b0b2e0 @raw={...}>
```


### Policies

```
client.policies
=>  [#<Threatstack::Policy::Policy:0x007fa262b0b2e0 @raw={...}> ]
client.policy
=>  #<Threatstack::Policy::Policy:0x007fa262b0b2e0 @raw={...}>
```

### Organizations

```
client.organizations
=>  [#<Threatstack::Organization::Organization:0x007fa262b0b2e0 @raw={...}> ]
```

### Audit Logs

```
client.logs
=>  [#<Threatstack::Log::Log:0x007fa262b0b2e0 @raw={...}>]
client.search('query')
=>  [#<Threatstack::Log::Log:0x007fa262b0b2e0 @raw={...}>]
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/getoutreach/threatstack.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
