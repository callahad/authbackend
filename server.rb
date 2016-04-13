#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

require 'base64'
require 'cgi'
require 'date'
require 'digest/sha1'
require 'openssl'
require 'uri'

require 'jwt'
require 'mock_redis'
require 'pony'
require 'sinatra/base'
require 'sinatra/json'
require 'sinatra/multi_route'
require 'sinatra/reloader'

class LetsAuth < Sinatra::Application
  register Sinatra::MultiRoute

  configure :development do
    register Sinatra::Reloader
    Pony.override_options = { :via => :test }
  end

  configure do
    set :redis, MockRedis.new

    # For v1, maybe read persistent key from disk / env? Generated as fallback?
    # Or maybe we want to automatically do key rotation, instead?
    puts 'Generating ephemeral keypair...'
    set :privkey, OpenSSL::PKey::RSA.generate(2048)
    puts settings.privkey
    set :pubkey, settings.privkey.public_key
    puts settings.pubkey
    set :kid, Digest::SHA1.hexdigest(settings.pubkey.to_s)

    # TODO: Allow alternative public-facing ports, or require 443?
    set :host, 'example.invalid'
  end

  get '/' do
    'Hello, World'
  end

  get '/.well-known/openid-configuration' do
    # See: http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

    json ({
      issuer:                   "https://#{settings.host}",
      authorization_endpoint:   "https://#{settings.host}/auth",
      jwks_uri:                 "https://#{settings.host}/jwks.json",
      scopes_supported:         %w{ openid email },
      claims_supported:         %w{ aud email email_verified exp iat iss sub },
      response_types_supported: %w{ id_token },
      response_modes_supported: %w{ fragment },
      grant_types_supported:    %w{ implicit },
      subject_types_supported:  %w{ public },
      id_token_signing_alg_values_supported: %w{ RS256 },

      # TODO: Include this documentation with the daemon, eventually.
      #service_documentation: '',
      #op_policy_uri: '',
      #op_tos_uri: '',
    })
  end

  route :get, :post, '/auth' do
    # See: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

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

    if params[:login_hint]
      unless valid_email?(params[:login_hint])
        # TODO: What protocol? acct:, mailto:, or none? Update error message.
        halt 422, 'invalid "login_hint", parameter must be a valid email address'
      end
    else 
      # FIXME: Implement this. Note that any re-submission won't have an Origin
      # header matching the third party website...
      halt 501, 'authentication without a "login_hint" is not yet supported'
    end

    confirmation_url = stage(
      params[:login_hint], params[:client_id], params[:redirect_uri],
      nonce: params[:nonce], state: params[:state]
    )

    send_link(params[:login_hint], params[:client_id], confirmation_url)

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

  def stage(email, origin, redirect, options = {})
    redis = settings.redis

    code = gen_code()

    key = "#{email}:#{origin}"

    kv_array = []
    kv_array.push 'redirect', redirect
    kv_array.push 'code', code
    kv_array.push 'tries', 0
    kv_array.push 'nonce', options[:nonce] if options[:nonce]
    kv_array.push 'state', options[:state] if options[:state]

    redis.multi do
      redis.hmset key, *kv_array
      redis.expire key, 60 * 15
    end

    URI::HTTPS.build(
      host: settings.host,
      path: '/confirm',
      query: "email=#{CGI::escape email}&origin=#{CGI::escape origin}&code=#{code}"
    ).to_s
  end

  def send_link(who, where, what)
    message = Pony.mail(
      to: who,
      from: "no-reply@#{settings.host}",
      subject: "Finish logging into #{where}",
      body: "Click this link to finish logging in:\n\n#{what}"
    )

    puts '-----BEGIN EMAIL MESSAGE-----'
    puts message.to_s
    puts '-----END EMAIL MESSAGE-----'
  end

  def gen_code()
    # For v1, we'll want to use a real CSPRNG and such.
    # We'll also want to calculate the entropy of each code.
    # Lastly, thanks Stack Overflow:
    # http://stackoverflow.com/questions/88311/how-best-to-generate-a-random-string-in-ruby#answer-493230
    charset = %w{ 2 3 4 6 7 9 a c d e f g h j k m n p q r t v w x y z }
    (0...6).map { charset.to_a[rand(charset.size)] }.join
  end

  get '/confirm' do
    # For v1, we need to be extremely careful and run these through the same
    # validations as they should have gone through on input at /auth.
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
    halt 401, 'Incorrect code' unless data['code'] == params[:code].downcase

    redis.del key

    id_token = build_id_token(params[:email], params[:origin], data['nonce'])

    base_uri = data['redirect'] + '#id_token=' + id_token
    base_uri += '&state=' + data['state'] if data['state']
    redirect base_uri, 302
  end

  def build_id_token(email, origin, nonce = nil)
    now = DateTime::now.strftime('%s').to_i
    validity = 60 * 10

    payload = {
      aud: origin,
      email: email,
      email_verified: email,
      exp: now + validity,
      iat: now,
      iss: "https://#{settings.host}",
      sub: email,
    }

    payload[:nonce] = nonce unless nonce.nil?

    headers = {}
    headers[:kid] = settings.kid if settings.kid
    JWT.encode payload, settings.privkey, 'RS256', headers
  end

  get '/jwks.json' do
    json ({
      keys: [{
        kty: 'RSA',
        alg: 'RS256',
        use: 'sig',
        kid: settings.kid,
        n: Base64.urlsafe_encode64([settings.pubkey.params['n'].to_s(16)].pack('H*')).gsub(/=*$/, ''),
        e: Base64.urlsafe_encode64([settings.pubkey.params['e'].to_s(16)].pack('H*')).gsub(/=*$/, '')
      }]
    })
  end
end
