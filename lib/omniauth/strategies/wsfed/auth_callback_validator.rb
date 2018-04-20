module OmniAuth
  module Strategies
    class WSFed
      class AuthCallbackValidator
        attr_accessor :auth_callback,
                      :wsfed_settings

        ISSUER_MISMATCH     = 'AuthN token issuer does not match configured issuer.'
        AUDIENCE_MISMATCH   = 'AuthN token audience does not match configured realm.'
        TOKEN_EXPIRED       = 'AuthN token has expired.'
        NO_CLAIMS           = 'AuthN token contains no claims.'
        NO_USER_IDENTIFIER  = 'AuthN token contains no user identifier. Verify that configured :id_claim setting is correct.'

        def initialize(auth_callback, wsfed_settings)
          self.auth_callback  = auth_callback
          self.wsfed_settings = wsfed_settings
        end

        def validate!
          validate_issuer!
          validate_audience!
          validate_token_expiration!
          validate_claims!
          validate_uid!

          true
        end

        def validate_issuer!
          unless auth_callback.issuer == wsfed_settings[:issuer_name]
            Rails.logger.debug "[OmniAuth::Strategies::WSFed::ValidationError] ISSUER_MISMATCH error. auth_callback.issuer: #{auth_callback.issuer}. wsfed_settings[:issuer_name]: #{wsfed_settings[:issuer_name]}"

            raise OmniAuth::Strategies::WSFed::ValidationError.new(ISSUER_MISMATCH)
          end
        end

        def validate_audience!
          unless auth_callback.audience == wsfed_settings[:realm]
            Rails.logger.debug "[OmniAuth::Strategies::WSFed::ValidationError] AUDIENCE_MISMATCH error. auth_callback.audience: #{auth_callback.audience}. wsfed_settings[:realm]: #{wsfed_settings[:realm]}"

            raise OmniAuth::Strategies::WSFed::ValidationError.new(AUDIENCE_MISMATCH)
          end
        end

        def validate_token_expiration!
          unless auth_callback.expires_at > Time.now.utc
            Rails.logger.debug "[OmniAuth::Strategies::WSFed::ValidationError] TOKEN_EXPIRED error. auth_callback.expires_at: #{auth_callback.expires_at}. Time.now.utc: #{Time.now.utc}"

            raise OmniAuth::Strategies::WSFed::ValidationError.new(TOKEN_EXPIRED)
          end
        end

        def validate_claims!
          if auth_callback.claims.blank?
            Rails.logger.debug "[OmniAuth::Strategies::WSFed::ValidationError] NO_CLAIMS error. auth_callback.claims: #{auth_callback.claims}"

            raise OmniAuth::Strategies::WSFed::ValidationError.new(NO_CLAIMS)
          end
        end

        def validate_uid!
          if auth_callback.name_id.blank?
            Rails.logger.debug "[OmniAuth::Strategies::WSFed::ValidationError] NO_USER_IDENTIFIER error. auth_callback.name_id: #{auth_callback.name_id}"

            raise OmniAuth::Strategies::WSFed::ValidationError.new(NO_USER_IDENTIFIER)
          end
        end
      end
    end
  end
end
