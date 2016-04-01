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
    #
    # Open question: WTF is a "Dynamic OpenID Provider," and are we one?
    #   If so, we have to support a bunch of response_types and grant_types
    #   that, frankly, we'd rather not support in the name of simplicity.
    #
    #   Specifically, if we can avoid being a dynamic provider, we can:
    #     - Drop the token_endpoint and registration_endpoint
    #     - Only support the id_token response_type
    #     - Only support the implicit grant_type
    #
    # Open question: Can we avoid supporting the 'email' scope?
    #   And if so, can we also drop the userinfo_endpoint, since all of the
    #   relevant info will be returned in the id_token?
    json ({
      'issuer'                 => settings.origin,
      'authorization_endpoint' => settings.origin + '/oauth2/auth',
      'token_endpoint'         => settings.origin + '/oauth2/token',
      'userinfo_endpoint'      => settings.origin + '/oauth2/userinfo',
      'jwks_uri'               => settings.origin + '/oidc/jwks',
      'registration_endpoint'  => settings.origin + '/oidc/register',

      # TODO: Email maybe optional, since our sub == email?
      'scopes_supported' => ['openid', 'email'],

      # TODO: Dynamic OpenID Providers require 'code' and 'token id_token'. :(
      'response_types_supported' => ['code', 'id_token', 'token id_token'],

      # TODO: Note that by default responses can be sent as either query args or
      # fragments, and we may need to support both. The query type seems to be
      # prohibited by the OAuth 2.0 spec for id_tokens:
      # http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#id_token

      # 'response_modes_supported' => ['query', 'fragment'],

      # TODO: Note that we only want to support the Implicit flow, but Dynamic
      # OpenID Providers must also support the authorization_code flow
      # http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

      # 'grant_types_supported' => ['authorization_code', 'implicit'],

      'subject_types_supported' => ['public'],
      'id_token_signing_alg_values_supported' => ['RS256'],

      # TODO: Include this documentation with the daemon, eventually.

      #'service_documentation' => '',
      #'op_policy_uri' => '',
      #'op_tos_uri' => '',
    })
  end

  get '/oauth2/auth' do
    'FIXME: Implement this endpoint.'
  end

  get '/oauth2/token' do
    # TODO: "REQUIRED unless only the Implicit Flow is used." So, not required?
    'FIXME: Implement this endpoint.'
  end

  get '/oauth2/userinfo' do
    # TODO: "RECOMMENDED" But... do we ever actually use this?
    'FIXME: Implement this endpoint.'
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

  get '/oidc/registration' do
    # TODO: "RECOMMENDED" But... can we avoid Dynamic Client Registration?
    'FIXME: Implement this endpoint.'
  end
end
