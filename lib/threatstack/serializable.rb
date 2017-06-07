module Threatstack
  module Serializable
    attr_reader :raw

    def self.included(base)
      base.extend ClassMethods
    end

    def initialize(raw)
      @raw = raw
    end

    def method_missing(m, *args)
      raw[m.to_s]
    end

    def attrs
      @attrs ||= self.class.default_attrs + raw.keys.map(&:to_sym)
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
