require 'omniauth'

module OmniAuth
  module Strategies
    class WSFed
      include OmniAuth::Strategy

      autoload :AuthRequest,            'omniauth/strategies/wsfed/auth_request'
      autoload :AuthCallback,           'omniauth/strategies/wsfed/auth_callback'
      autoload :AuthCallbackValidator,  'omniauth/strategies/wsfed/auth_callback_validator'
      autoload :SAML2Token,             'omniauth/strategies/wsfed/saml_2_token'
      autoload :SAML1Token,             'omniauth/strategies/wsfed/saml_1_token'
      autoload :ValidationError,        'omniauth/strategies/wsfed/validation_error'
      autoload :XMLSecurity,            'omniauth/strategies/wsfed/xml_security'

      WS_TRUST    = 'http://schemas.xmlsoap.org/ws/2005/02/trust'
      WS_POLICY   = 'http://schemas.xmlsoap.org/ws/2004/09/policy'

      # Issues passive WS-Federation redirect for authentication.
      def request_phase
        settings = options.dup
        settings[:reply] ||= callback_url
        auth_request = OmniAuth::Strategies::WSFed::AuthRequest.new(settings, :whr => @request.params['whr'])
        redirect(auth_request.redirect_url)
      end

      # Parse SAML token.
      def callback_phase
        begin
          validate_callback_params(@request)

          wsfed_callback = request.params[response_param]
          wsfed_callback = Base64.decode64(wsfed_callback) if options[:response_in_base64]

          signed_document = OmniAuth::Strategies::WSFed::XMLSecurity::SignedDocument.new(wsfed_callback, options)
          signed_document.validate(get_fingerprint, false)

          auth_callback = OmniAuth::Strategies::WSFed::AuthCallback.new(wsfed_callback, options)
          validator     = OmniAuth::Strategies::WSFed::AuthCallbackValidator.new(auth_callback, options)

          validator.validate!

          @name_id = auth_callback.name_id
          @claims  = auth_callback.attributes

          super

        rescue ArgumentError => e
          fail!(:invalid_response, e)
        rescue OmniAuth::Strategies::WSFed::ValidationError => e
          fail!(:invalid_authn_token, e)
        end

      end

      # OmniAuth DSL methods.
      uid   { @name_id }
      info  { @claims }
      extra { { response_param => request.params[response_param] } }

    private

      def response_param
        options[:response_param] || :wresult
      end

      def get_fingerprint
        if options[:idp_cert_fingerprint]
          options[:idp_cert_fingerprint]
        else
          cert = OpenSSL::X509::Certificate.new(options[:idp_cert].gsub(/^ +/, ''))
          Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(':')
        end
      end

      def validate_callback_params(request)
        if request.params[response_param].nil? || request.params[response_param].empty?
          raise OmniAuth::Strategies::WSFed::ValidationError.new("AuthN token (#{response_param}) missing in callback.")
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'wsfed', 'WSFed'
