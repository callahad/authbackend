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
end
