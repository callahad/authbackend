#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

require 'base64'
require 'digest/sha1'
require 'openssl'
require 'uri'

require 'jwt'
require 'mock_redis'
require 'sinatra/base'
require 'sinatra/json'
require 'sinatra/multi_route'
require 'sinatra/reloader'

class LetsAuth < Sinatra::Application
  register Sinatra::MultiRoute

  configure :development do
    register Sinatra::Reloader
  end

  configure do
    set :redis, MockRedis.new

    # FIXME: Attempt to read persistent key from disk, env vars, or something.
    # Generate ephemeral keys as a fallback.
    puts 'Generating ephemeral keypair...'
    set :privkey, OpenSSL::PKey::RSA.generate(2048)
    set :pubkey, settings.privkey.public_key

    # TODO: Allow alternative public-facing ports, or require 443?
    set :host, 'example.invalid'
  end

  get '/' do
    'Hello, World'
  end

  get '/.well-known/openid-configuration' do
    # Parameters from the OpenID Connect Discovery 1.0 spec at:
    # http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    json ({
      'issuer'                 => "https://#{settings.host}",
      'authorization_endpoint' => "https://#{settings.host}/oauth2/auth",
      'jwks_uri'               => "https://#{settings.host}/oidc/jwks",
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

  route :get, :post, '/oauth2/auth' do
    # See: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    #
    # Things we don't actually care about, but should add for OIDC compliance:
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
    #   id_token_hint: Optional. We won't support it. Fail with "login_required"

    unless params[:scope].class == String && params[:scope].split(' ').include?('openid')
      halt 422, '"scope" parameter must be present and include "openid"'
    end

    unless params[:response_type].class == String && params[:response_type].split(' ') == ['id_token']
      halt 422, '"response_type" parameter must be present, and only "id_token" is supported'
    end

    unless params[:client_id].class == String && valid_origin?(params[:client_id])
      halt 422, '"client_id" parameter must be present, must be a valid HTTP origin, and must match the Origin HTTP header'
    end

    unless params[:redirect_uri].class == String && ok_redirect?(params[:client_id], params[:redirect_uri])
      halt 422, '"redirect_uri" parameter must be present, and a valid URI within the "client_id" origin'
    end

    unless params[:response_mode].nil? || params[:response_mode] == 'fragment'
      halt 422, 'invalid "response_mode", only "fragment" is supported'
    end

    response_params = {}

    if params[:state]
      response_params[:state] = params[:state]
    end

    token_params = {}

    if params[:nonce]
      token_params[:nonce] = params[:nonce]
    end

    if params[:login_hint]
      unless valid_email?(params[:login_hint])
        # TODO: What protocol? acct:, mailto:, or none? Update error message.
        halt 422, 'invalid "login_hint", parameter must be a valid email address'
      end
    else 
      # FIXME: Implement this
      halt 501, 'authentication without a "login_hint" is not yet supported'
    end

    halt 501, 'authentication is not yet implemented'
  end

  def valid_origin?(client_id)
    # For v1, we'll want something more rigorous / well thought out here
    client_id == request.env['HTTP_ORIGIN'] # The 'Origin: ...' header
  end

  def ok_redirect?(origin,uri)
    # FIXME: Implement this
    true
  end

  def valid_email?(email)
    # If it's good enough for Michael Hartl...
    # https://www.railstutorial.org/book/_single-page#sec-format_validation
    # For v1, we'll want a library with an actual parser and/or DNS checks.
    # In node.js, https://github.com/hapijs/isemail is a good option.
    valid_email_regex = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
    email =~ valid_email_regex
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
