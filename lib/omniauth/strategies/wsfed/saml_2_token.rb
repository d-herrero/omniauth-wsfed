module OmniAuth
  module Strategies
    class WSFed
      class SAML2Token
        attr_accessor :document

        def initialize(document)
          @document = document
        end

        def audience
          # We capture any possible error to prevent check problems.
          begin
            # We look in "//t:RequestSecurityTokenResponse/wsp:AppliesTo -> //EndpointReference/Address" first.
            applies_to = REXML::XPath.first(document, '//t:RequestSecurityTokenResponse/wsp:AppliesTo', { 't' => WS_TRUST, 'wsp' => WS_POLICY })
            result     = applies_to.present? ? REXML::XPath.first(applies_to, '//EndpointReference/Address') : nil

            # If nothing is found, we look in "//samlp:Response/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience" instead.
            result     = REXML::XPath.first(document, '//samlp:Response/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience') unless result

            result ? result.text : nil
          rescue
            nil
          end
        end

        def issuer
          # As we did in #audience, we look in several paths and capture errors.
          begin
            result = REXML::XPath.first(document, '//Assertion/Issuer')
            result = REXML::XPath.first(document, '//samlp:Response/saml:Issuer') unless result

            result ? result.text : nil
          rescue
            nil
          end
        end

        def claims
          # Same as #audience and #issuer.
          stmt_element = REXML::XPath.first(document, '//Assertion/AttributeStatement')
          stmt_element = REXML::XPath.first(document, '//samlp:Response/saml:Assertion/saml:AttributeStatement') unless stmt_element

          return {} unless stmt_element

          {}.tap do |result|
            stmt_element.elements.each do |attr_element|
              name  = attr_element.attributes['Name']

              if attr_element.elements.count > 1
                value = []
                attr_element.elements.each { |element| value << element.text }
              else
                value = attr_element.elements.first.text.to_s.lstrip.rstrip
              end

              result[name] = value
            end
          end
        end
      end
    end
  end
end
