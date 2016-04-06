#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

require 'base64'
require 'digest/sha1'
require 'openssl'

require 'jwt'
require 'mock_redis'
require 'sinatra/base'
require 'sinatra/json'

class LetsAuth < Sinatra::Application
  configure do
    set :redis, MockRedis.new

    # FIXME: Attempt to read persistent key from disk, env vars, or something.
    # Generate ephemeral keys as a fallback.
    puts 'Generating ephemeral keypair...'
    set :privkey, OpenSSL::PKey::RSA.generate(2048)
    set :pubkey, settings.privkey.public_key

    set :origin, 'https://example.invalid'
  end

  get '/' do
    'Hello, World'
  end

  get '/.well-known/openid-configuration' do
    # Parameters from the OpenID Connect Discovery 1.0 spec at:
    # http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    json ({
      'issuer'                 => settings.origin,
      'authorization_endpoint' => settings.origin + '/oauth2/auth',
      'jwks_uri'               => settings.origin + '/oidc/jwks',
      'scopes_supported' => ['openid'],
      'response_types_supported' => ['id_token'],
      'response_modes_supported' => ['fragment'],
      'grant_types_supported' => ['implicit'],
      'subject_types_supported' => ['public'],
      'id_token_signing_alg_values_supported' => ['RS256'],

      # TODO: Include this documentation with the daemon, eventually.
      #'service_documentation' => '',
      #'op_policy_uri' => '',
      #'op_tos_uri' => '',
    })
  end

  get '/oauth2/auth' do
    # Parse from application/x-www-form-urlencoded serialization of query args
    'FIXME: Implement this endpoint.'
  end

  post '/oauth2/auth' do
    # Parse from application/x-www-form-urlencoded serialization of request body
    'FIXME: Implement this endpoint.'
  end

  def handle_oauth2(&params)
    # See: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    #
    # OAuth Parameters:
    #   scope: Fail if array doesn't include 'openid'. Ignore all other members.
    #   response_type: Fail if not `id_token`.
    #   client_id: Let's use the RP's origin. E.g., https://example.com:12443
    #   redirect_uri: Must be within the RP's origin. Plus further validations.
    #   state: Opaque value. Reflect it back to the RP in response args
    #   response_mode: Ignore it. Spec requires that id_token uses 'fragment'
    #
    # OpenID Connect Parameters:
    #   nonce: Opaque value. Reflect it back to the RP inside the id_token.
    #   display: Ignore it.
    #   prompt: Optional, space-delimited string.
    #     Possible values: "none", "login", "consent", or "select_account"
    #
    #     Generally, these don't make sense for us, since we don't have durable
    #     state at the daemon. We could support some of these options in the
    #     future, but it probably doesn't make sense for v1. So, ignore this.
    #
    #     Also: "none" in combination any other option is an error; fail.
    #     When failing, fail according to Section 3.1.2.6.
    #   max_age: Optional, we'll always re-auth for v1, so we can ignore this.
    #     We must return an "auth_time" claim in the id_token.
    #   ui_locales: Optional, ignore for now.
    #   id_token_hint: Optional. We won't support it. Fail with "login_required"
    #   login_hint: Optional, but we want to strongly encourage it.
    #     Spec says that the value MAY be a phone numbers. No. Reject those.
    #   acr_value: Optional; ignore it. Too much bureaucratic overhead for us.
    #   claims: Optional JSON object of requested claims. We don't support this.
    #     NOTE, we may want to support the email scope and inline its claims
    #   request: All of the above, rolled up as a JWT. We don't support this.
    #   request_uri: Ditto, but as a reference to a URI with a JWT. Ignore it.
    #   registration: Endpoint for RPs to dynamically register with us. Ignore.
    #     We may need to bring this in if we can't allow unregistered clients.
  end

  get '/oidc/jwks' do
    json ({
      'keys' => [{
        'kty' => 'RSA',
        'alg' => 'RS256',
        'use' => 'sig',
        'kid' => Digest::SHA1.hexdigest(settings.pubkey.to_s),
        'n' => Base64.urlsafe_encode64([settings.pubkey.params['n'].to_s(16)].pack('H*')).gsub(/=*$/, ''),
        'e' => Base64.urlsafe_encode64([settings.pubkey.params['e'].to_s(16)].pack('H*')).gsub(/=*$/, '')
      }]
    })
  end
end
