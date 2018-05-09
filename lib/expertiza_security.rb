module ExpertizaSecurity
  module Security
    extend ActiveSupport::Concern

    included do
      attr_accessor :encrypted_attributes

      before_save :encrypt
      after_initialize :decrypt
      after_save :decrypt

      @encrypted_attributes = Array.new

      Attributes.encrypted_attributes = Array.new
      Attributes.hashed_attributes = Array.new

      class_eval do
        [:is_encrypted?, :is_hashed?, :has_password?, :skip_auto_organization_id?].collect { |method_name| define_method(method_name) { false }  }
      end

      def self.attr_encrypted(attr_encrypted)
        Attributes.encrypted_attributes.push attr_encrypted unless Attributes.encrypted_attributes.include? attr_encrypted

        class_eval do
          def encrypted_attributes
            Attributes.encrypted_attributes
          end

          def is_encrypted?
            true
          end
        end
      end

      def self.attr_hashed(attr_hashed)
        Attributes.hashed_attributes.push attr_hashed unless Attributes.hashed_attributes.include? attr_hashed

        class_eval do
          def hashed_attributes
            Attributes.hashed_attributes
          end

          def is_hashed?
            true
          end
        end
      end

      def self.has_password(password_digest_attribute)
        Attributes.password_digest_attribute = password_digest_attribute

        class_eval do
          def authenticate(password)
            authenticate_password(password)
          end

          def has_password?
            true
          end
        end
      end

      def decrypt
        if self.is_encrypted? && !self.new_record?
          @salt = self.has_attribute?(:salt) ? self.salt ||= KeyManagement.salt : KeyManagement.salt if self.is_encrypted? || self.is_hashed?

          if self.has_attribute? :data_encryption_key
            if self.data_encryption_key
              @crypt = Crypt.new(KeyManagement.key_encryption_key, @salt)

              data_encryption_key = @crypt.decrypt(self.data_encryption_key)
            else
              data_encryption_key = KeyManagement.key_encryption_key
            end
          else
            data_encryption_key = KeyManagement.key_encryption_key
          end

          if !data_encryption_key.nil? && self.encrypted_attributes.respond_to?(:each)
            @crypt = Crypt.new(data_encryption_key, @salt)

            self.encrypted_attributes.uniq.each do |encrypted_attribute|
              plain_text = @crypt.decrypt(self.read_attribute(encrypted_attribute))
              self.assign_attributes({encrypted_attribute => plain_text}) if self.has_attribute?(encrypted_attribute) && plain_text
            end
          end
        end
      end

      def encrypt
        if self.new_record?
          self.uuid = KeyManagement.generate_uuid if self.has_attribute?(:uuid) && (!self.uuid || self.new_record?)
          self.salt = KeyManagement.generate_salt if self.has_attribute?(:salt) && (!self.salt || self.new_record?)
          @crypt = Crypt.new(KeyManagement.key_encryption_key, self.salt)
          self.data_encryption_key = @crypt.encrypt(KeyManagement.generate_data_encryption_key) if self.has_attribute?(:data_encryption_key)  && (!self.data_encryption_key || self.new_record?)
        end

        @salt = self.has_attribute?(:salt) ? self.salt ||= KeyManagement.salt : KeyManagement.salt if self.is_encrypted? || self.is_hashed?

        if self.is_hashed? && !self.salt.nil?
          if self.hashed_attributes.respond_to?(:each)
            self.hashed_attributes.each do |hashed_attribute|
              self.send("#{hashed_attribute}=", Crypt.hash_message(self.read_attribute(hashed_attribute), @salt)) if self.has_attribute?(hashed_attribute) && self.send("#{hashed_attribute}_changed?")
            end
          end
        end

        if self.is_encrypted?
          if !self.new_record? && self.has_attribute?(:salt) && self.has_attribute?(:data_encryption_key)
            if self.salt_changed? && !self.data_encryption_key_changed?
              last_data_encryption_key = Crypt.decrypt(self.data_encryption_key, KeyManagement.key_encryption_key, self.changes[:salt][0])
              self.data_encryption_key = Crypt.encrypt(last_data_encryption_key , KeyManagement.key_encryption_key, @salt) if model.has_attribute?(:data_encryption_key)
            elsif self.data_encryption_key_changed?
              self.data_encryption_key = Crypt.encrypt(self.data_encryption_key , KeyManagement.key_encryption_key, @salt) if model.has_attribute?(:data_encryption_key)
            end
          end

          if self.has_attribute? :data_encryption_key
            @crypt = Crypt.new(KeyManagement.key_encryption_key, @salt)
            data_encryption_key = self.data_encryption_key ? @crypt.decrypt(self.data_encryption_key) : KeyManagement.key_encryption_key
          else
            data_encryption_key = KeyManagement.key_encryption_key
          end

          if self.encrypted_attributes.respond_to?(:each)
            @crypt = Crypt.new(data_encryption_key, @salt)

            self.encrypted_attributes.each do |encrypted_attribute|
              self.send("#{encrypted_attribute}=", @crypt .encrypt(self.read_attribute(encrypted_attribute))) if self.has_attribute?(encrypted_attribute) && self.send("#{encrypted_attribute}")
            end
          end
        end
      end
    end

    class Attributes
      class << self
        def encrypted_attributes=(encrypted_attributes)
          @encrypted_attributes = encrypted_attributes
        end

        def encrypted_attributes
          @encrypted_attributes
        end

        def password_digest_attribute=(password_digest_attribute)
          @password_digest_attribute = password_digest_attribute
        end

        def password_digest_attribute
          @password_digest_attribute
        end

        def hashed_attributes=(hashed_attributes)
          @hashed_attributes = hashed_attributes
        end

        def hashed_attributes
          @hashed_attributes
        end
      end
    end

    class Crypt
      def initialize(key,salt)
        @crypt = ActiveSupport::MessageEncryptor.new(ActiveSupport::KeyGenerator.new(key).generate_key(salt, 32))
      end

      def encrypt(message)
        @crypt.encrypt_and_sign(message)
      end

      def decrypt(message)
        @crypt.decrypt_and_verify(message)
      rescue ActiveSupport::MessageVerifier::InvalidSignature
        nil
      end

      class << self
        def hash_message(message, salt)
          sha256 = OpenSSL::Digest::SHA256.new
          sha256.hexdigest("#{salt}-b+Em^#qmx$rT'X}.7Qhq<z-#{message}")
        end

        def verify_hashed_message(hashed_message, message, salt)
          hash_message message, salt == hashed_message
        end
      end
    end

    class KeyManagement
      class << self
        def key_encryption_key
          SECRET_KEYS['00004']
        end

        def salt
          SECRET_SALTS['00005']
        end

        def generate_uuid
          SecureRandom.uuid
        end

        def generate_salt
          SecureRandom.hex(32)
        end

        def generate_data_encryption_key
          SecureRandom.hex(64).to_s
        end
      end
    end
  end
end