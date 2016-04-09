#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

require 'base64'
require 'cgi'
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

    puts "Return URL is: " +
    stage(params[:login_hint], params[:client_id], params[:redirect_uri])

    return 200, "Please check your email at #{params[:login_hint]}"
  end

  def valid_origin?(client_id)
    # For v1, we'll want something more rigorous / well thought out here
    uri = URI.parse(client_id)

    return false if uri.to_s != client_id
    return false if uri.userinfo || !uri.path.empty? || uri.query || uri.fragment
    return false unless uri.scheme && uri.host && uri.port

    client_id == request.env['HTTP_ORIGIN'] # The 'Origin: ...' header
  end

  def ok_redirect?(origin,redirect)
    # For v1, we'll want a much more rigorous, tested validator here

    # TODO: I think there's something in the spec about how we're supposed to
    # handle query args and/or fragments in the redirect_uri. Mirror them?
    # For now, fail if they exist.

    o_uri = URI.parse(origin)
    r_uri = URI.parse(redirect)

    return false if r_uri.to_s != redirect
    return false if r_uri.userinfo || r_uri.query || r_uri.fragment
    return false unless r_uri.scheme && r_uri.host && r_uri.port

    return false unless r_uri.scheme == o_uri.scheme &&
                        r_uri.host == o_uri.host &&
                        r_uri.port == o_uri.port

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

  def stage(email, origin, redirect)
    redis = settings.redis

    code = gen_code()

    key = "#{email}:#{origin}"

    redis.multi do
      redis.hmset key,
        'redirect', redirect,
        'code', code,
        'tries', 0
      redis.expire key, 60 * 15
    end

    URI::HTTPS.build(
      :host => settings.host,
      :path => '/verify',
      :query => "email=#{CGI::escape email}&origin=#{CGI::escape origin}&code=#{code}"
    ).to_s
  end

  def gen_code()
    # For v1, we'll want to use a real CSPRNG and such.
    # We'll also want to calculate the entropy of each code.
    # Lastly, thanks Stack Overflow:
    # http://stackoverflow.com/questions/88311/how-best-to-generate-a-random-string-in-ruby#answer-493230
    charset = %w{ 2 3 4 6 7 9 A C D E F G H J K M N P Q R T V W X Y Z }
    (0...6).map { charset.to_a[rand(charset.size)] }.join
  end

  get '/verify' do
    # For v1, we need to be extremely careful and run these through the same
    # validations as they should have gone through on input at /oauth2/auth.
    # Also, we need to audit the rate limiting, info leaks, etc of this endpoint
    redis = settings.redis

    halt 422, 'Missing or malformed parameters' unless params[:email] && params[:origin] && params[:code]

    key = "#{params[:email]}:#{params[:origin]}"

    data, attempt = redis.multi do
      redis.hgetall key
      redis.hincrby key, 'tries', 1
    end

    halt 401, 'Unknown or expired credentials' if data.empty?
    halt 401, 'Too many failed attempts' if (attempt > 3)
    halt 401, 'Incorrect code' unless data['code'] == params[:code].upcase

    redis.del key

    # FIXME: Sign and append JWT to redirect_uri, also make sure to pass through
    # state as a query arg and nonce inside the jwt
    redirect data['redirect'], 302
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
