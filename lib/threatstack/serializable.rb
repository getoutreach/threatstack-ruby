module Threatstack
  module Serializable
    attr_reader :client, :raw

    def self.included(base)
      base.extend ClassMethods
    end

    def initialize(raw, client, entity: nil)
      @client = client
      @raw = raw
      @entity = entity
    end

    def method_missing(m, *args)
      raw[m.to_s] || raw[camelize(m.to_s)]
    end

    def attrs
      @attrs ||= self.class.default_attrs
    end

    def camelize(str)
      string = str.sub(/^(?:(?=\b|[A-Z_])|\w)/) { $&.downcase }
      string.gsub(/(?:_|(\/))([a-z\d]*)/) { "#{$1}#{$2.capitalize}" }.gsub('/', '::')
    end
    module ClassMethods
      def attributes(*args)
        @default_attrs = args
      end

      def default_attrs
        @default_attrs ||= []
      end
    end
  end
end
