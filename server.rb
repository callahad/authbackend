#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

require 'sinatra/base'
require 'sinatra/json'
require 'jwt'
require 'mock_redis'
require 'openssl'
require 'base64'

class LetsAuth < Sinatra::Application
  configure do
    set :redis, MockRedis.new

    # FIXME: Attempt to read persistent key from disk.
    # Generate ephemeral keys as a fallback.
    puts 'Generating ephemeral keypair...'
    set :privkey, OpenSSL::PKey::RSA.generate(2048)
    set :pubkey, settings.privkey.public_key
  end

  get '/' do
    'Hello, World'
  end

  get '/.well-known/openid-configuration' do
    # FIXME: Make configurable + add remaining necessary keys. More info at:
    #   https://github.com/letsauth/oidc-prototype/issues/3
    #   https://accounts.google.com/.well-known/openid-configuration
    json ({
      :issuer => 'https://example.invalid',
      :authorization_endpoint => 'https://example.invalid/oauth2/auth',
      :jwks_uri => 'https://example.invalid/meta/jwks'
    })
  end

  get '/oauth2/auth' do
    'FIXME: Implement this endpoint.'
  end

  get '/meta/jwks' do
    json ({
      :keys => [{
        :kty => 'RSA',
        :alg => 'RS256',
        :use => 'sig',
        :kid => 'FIXME -- Generate a unique key id',
        :n => Base64.urlsafe_encode64([settings.pubkey.params['n'].to_s(16)].pack('H*')).gsub(/=*$/, ''),
        :e => Base64.urlsafe_encode64([settings.pubkey.params['e'].to_s(16)].pack('H*')).gsub(/=*$/, '')
      }]
    })
  end
end
