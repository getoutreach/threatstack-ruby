# Threatstack

Threatstack is a tool for monitoring your infrastructure and hosts for malicious or suspicious activity. They have this handy little API that I decided to write a Ruby wrapper for. This is a very thin wrapper that only transforms keys for the purpose of changing them to snake_case like the rest of the ruby world. Otherwise, this maps very closely to the API docs found here: https://apidocs.threatstack.com/v2

### NOTE: From version 1.0.0 onward, only Threatstack API v2 is supported

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
client = Threatstack::Client.new(organization_id: ORG_ID, api_key: API_KEY)
[threatstack] main> ts.alerts("active").first.attrs
=> [:id,
 :title,
 :type,
 :created_at,
 :event_count,
 :is_dismissed,
 :dismissed_at,
 :dismissed_reason,
 :dismissed_reason_text,
 :dismissed_by,
 :severity,
 :agent_id,
 :rule_id,
 :ruleset_id,
 :event_ids]

 ```

### Alerts

```
client = Threatstack::Client.new(organization_id: ORG_ID)
## All these are optional url params. See the Threatstack API Docs
alert = client.alerts("active", start: 3.days.ago, end: Time.now, count: 5).last
=> #<Threatstack::Alert:0x007fde0b01cbd8
 @raw=
  {"created_at"=>1496850520000,
   "expires_at"=>1496936920000,
   "last_updated_at"=>"2017-06-07T16:03:56.270Z",
   "count"=>4,
   "title"=>"CloudTrail Activity : EC2 Service Policy Changes : CreateVolume by ryan_canty",
   ...
count = alert.count
=> 4
```

You can also limit the response if that's important to you:

```
client.alerts("active", fields: ['title', 'alerts'])
=> [#<Threatstack::Alert:0x007fd61348c768
  @raw={"title"=>"CloudTrail Activity (IAM Policy Changes) : CreateAccessKey by ryan_canty", "severity"=>2}>]
```

You can also get a single alert by id using:

```
client.alert('1234567890')
```

### Agents

```
client.agents('online')
=>  [#<Threatstack::Response:0x007fa262b0b2e0 @raw={...}> ]
client.agent('123123123')
=>  #<Threatstack::Agent:0x007fa262b0b2e0 @raw={...}>
```

### Vulnerabilities

```
client.vulnerabilities
client.vulnerability('CVE-123')
```
## TODO: Write docs for all the things (contributions welcome)


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/getoutreach/threatstack.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
