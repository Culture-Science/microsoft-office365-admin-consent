require "omniauth/strategies/oauth2"

module OmniAuth
  module Strategies
    class MicrosoftOffice365AdminConsent < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE=".default"

      option :name, :microsoft_office365_admin_consent

      option :client_options, {
        site:          "https://login.microsoftonline.com",
        authorize_url: "/common/adminconsent",
        token_url:     "/common/oauth2/v2.0/token",
      }

      def build_access_token
        token = get_access_token
        ::OAuth2::AccessToken.new(client, token["access_token"], expires_in: token["expires_in"])
      end

      def get_access_token
        tenant = options["tenant"] || request.params["tenant"]
        sleep 10 # Microsoft's Graph API doesn't immediately recognize that the user gave consent :'(
        response = Faraday.post("https://login.microsoftonline.com/#{tenant}/oauth2/v2.0/token", client_id: options[:client_id], client_secret: options[:client_secret], grant_type: "client_credentials", scope: ".default")
        JSON.parse(response.body)
      end

      option :authorize_options, %w[scope domain_hint]

      uid { raw_info.dig("value", 0, "id") }

      info do
        {
          email:           raw_info.dig("value", 0, "technicalNotificationMails", 0) ,
          display_name:    raw_info.dig("value", 0, "displayName"),
        }
      end

      extra do
        {
          "raw_info" => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get("https://graph.microsoft.com/v1.0/organization").parsed
      end

      def authorize_params
        super.tap do |params|
          %w[display domain_hint scope auth_type].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end

          params[:scope] ||= DEFAULT_SCOPE
        end
      end

      private

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      def avatar_file
      #   photo = access_token.get("https://graph.microsoft.com/v1.0/me/photo/$value")
      #   ext   = photo.content_type.sub("image/", "") # "image/jpeg" => "jpeg"

      #   Tempfile.new(["avatar", ".#{ext}"]).tap do |file|
      #     file.binmode
      #     file.write(photo.body)
      #     file.rewind
      #   end

      # rescue ::OAuth2::Error => e
      #   if e.response.status == 404 # User has no avatar...
      #     return nil
      #   elsif e.code['code'] == 'GetUserPhoto' && e.code['message'].match('not supported')
      #     nil
      #   else
      #     raise
      #   end
      end
    end
  end
end
