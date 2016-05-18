#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

require 'base64'
require 'cgi'
require 'date'
require 'digest/sha1'
require 'openssl'
require 'securerandom'
require 'uri'

require 'jwt'
require 'mock_redis'
require 'redis'
require 'omniauth'
require 'omniauth-google-oauth2'
require 'pony'
require 'sinatra/base'
require 'sinatra/json'
require 'sinatra/multi_route'
require 'sinatra/reloader'
require 'tilt/erb'

class LetsAuth < Sinatra::Application
  register Sinatra::MultiRoute

  configure do
    enable :sessions

    set :views, File.dirname(__FILE__) + '/views'

    OmniAuth.config.failure_raise_out_environments = []

    use OmniAuth::Builder do
      provider :google_oauth2,
        ENV['GOOGLE_CLIENT_ID'], ENV['GOOGLE_CLIENT_SECRET'],
        { prompt: 'consent', access_type: 'online' }
    end

    if ENV['REDIS_URL'] then
      set :redis, Redis.new(url: ENV['REDIS_URL'])
    else
      set :redis, MockRedis.new
    end

    if ENV['LETSAUTH_PRIVATE_KEY'] then
      puts 'Loading keypair from environment...'
      set :privkey, OpenSSL::PKey::RSA.new(ENV['LETSAUTH_PRIVATE_KEY'])
    else
      puts 'Generating ephemeral keypair...'
      set :privkey, OpenSSL::PKey::RSA.generate(2048)
    end
    puts settings.privkey
    set :pubkey, settings.privkey.public_key
    puts settings.pubkey
    set :kid, Digest::SHA1.hexdigest(settings.pubkey.to_s)

    set :scheme, 'https'
    set :host, 'example.invalid'
    set :port, 443

    set :host, "#{ENV['HEROKU_APP_NAME']}.herokuapp.com" if ENV['HEROKU_APP_NAME']

    set :from, 'letsauth@dancallahan.info'

    Pony.options = {
      from: settings.from,
      via: :smtp,
      via_options: {
        address: ENV['POSTMARK_SMTP_SERVER'],
        port: 587,
        enable_starttls_auto: true,
        user_name: ENV['POSTMARK_API_KEY'],
        password: ENV['POSTMARK_API_KEY'],
        authentication: 'plain',
        domain: settings.host
      }
    }
  end

  configure :development do
    register Sinatra::Reloader

    set :scheme, 'http'
    set :host, '127.0.0.1'
    set :port, 9292

    Pony.override_options = { :via => :test }

    set :protection, :except => :frame_options
  end

  get '/' do
    'Hello, World'
  end

  get '/.well-known/openid-configuration' do
    # See: http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

    json ({
      issuer:                   "#{settings.scheme}://#{settings.host}",
      authorization_endpoint:   "#{settings.scheme}://#{settings.host}/auth",
      jwks_uri:                 "#{settings.scheme}://#{settings.host}/jwks.json",
      scopes_supported:         %w{ openid email },
      claims_supported:         %w{ aud email email_verified exp iat iss sub },
      response_types_supported: %w{ id_token },
      response_modes_supported: %w{ form_post },
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

    # For v1, rate limit this API so we can't be used to spam people

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

    if params[:login_hint].end_with? '@gmail.com'
      # FIXME: Ugly hack; only allows a single in-flight Gmail auth per user
      #
      # For traditional email loop confirmations, we embed the "email:rp" pair
      # right in the link parameters. To get the same from Google, we'll need
      # to round-trip the rp's origin in a "nonce" parameter that we send.
      #
      # However, the Omniauth Google OAuth2 strategy, in addition to requiring
      # Contacts and G+ API entitlements, doesn't support sending nonces.
      #
      # Find or craft a better lib for v1.
      stage(
        # FIXME: Normalize the login_hint in a gmail-specific manner
        params[:login_hint], 'GOOGLE_OAUTH2', params[:redirect_uri],
        nonce: params[:nonce], state: params[:state]
      )

      return redirect "/auth/google_oauth2?login_hint=#{params[:login_hint]}"
    else
      confirmation_url = stage(
        # FIXME: Normalize the login_hint
        params[:login_hint], params[:client_id], params[:redirect_uri],
        nonce: params[:nonce], state: params[:state], generate_link: true
      )

      send_link(params[:login_hint], params[:client_id], confirmation_url)

      return erb :auth, { locals: {
        email: params[:login_hint],
        origin: params[:client_id],
      } }
    end
  end

  def valid_origin?(client_id)
    # For v1, we'll want something more rigorous / well thought out here
    uri = URI.parse(client_id)

    return false if uri.to_s != client_id
    return false if uri.userinfo || !uri.path.empty? || uri.query || uri.fragment
    return false unless uri.scheme && uri.host && uri.port

    # FIXME: When *is* Origin sent? Doesn't seem to be sent on form submission.
    # client_id == request.env['HTTP_ORIGIN'] # The 'Origin: ...' header

    return true
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

    # FIXME: Normalize the email address
    key = "#{email}:#{origin}"

    kv_array = []
    kv_array.push 'redirect', redirect
    kv_array.push 'nonce', options[:nonce] if options[:nonce]
    kv_array.push 'state', options[:state] if options[:state]

    if options[:generate_link]
      kv_array.push 'code', code
      kv_array.push 'tries', 0
    end

    redis.multi do
      redis.hmset key, *kv_array
      redis.expire key, 60 * 15
    end

    if options[:generate_link]
      builder = settings.scheme == 'http' ? URI::HTTP : URI::HTTPS

      return builder.build(
        host: settings.host,
        port: settings.port,
        path: '/confirm',
        query: "email=#{CGI::escape email}&origin=#{CGI::escape origin}&code=#{code}"
      ).to_s
    else 
      return true
    end
  end

  def send_link(who, where, what)
    code = CGI.parse(URI.parse(what).query)['code'].first

    message = Pony.mail(
      to: who,
      from: settings.from,
      subject: "Code: #{code} - Finish logging into #{where}",
      body: "Enter your login code:\n\n    #{code}\n\nOr click this link to finish logging in:\n\n    #{what}"
    )

    puts '-----BEGIN EMAIL MESSAGE-----'
    puts message.to_s
    puts '-----END EMAIL MESSAGE-----'
  end

  def gen_code()
    # For v1, we'll want to make an explicit decision re: entropy
    # We'll also want to calculate the entropy of each code.
    # Lastly, thanks Stack Overflow:
    # http://stackoverflow.com/questions/88311/how-best-to-generate-a-random-string-in-ruby#answer-493230
    charset = %w{ 2 3 4 6 7 9 a c d e f g h j k m n p q r t v w x y z }
    (0...6).map { charset.to_a[SecureRandom.random_number(charset.size)] }.join
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

    halt 401, 'Unknown or expired credentials' if data['code'].nil?
    halt 401, 'Too many failed attempts' if (attempt > 3)
    halt 401, 'Incorrect code' unless data['code'] == params[:code].downcase

    redis.del key

    id_token = build_id_token(params[:email], params[:origin], data['nonce'])

    return erb :forward, { locals: {
      return_uri: data['redirect'],
      id_token: id_token,
      state: data['state'],
    } }
  end

  get '/auth/failure' do
    # FIXME: Stash the RP origin in a session cookie so we can show an error
    # page with a friendly "Return to ..." link.
    'Login cancelled'
  end

  get '/auth/google_oauth2/callback' do
    redis = settings.redis

    email = request.env['omniauth.auth'].info.email

    # FIXME: Normalize the email address in a gmail-specific manner
    key = "#{email}:GOOGLE_OAUTH2"
    data = redis.hgetall key

    # TODO: Think about upgrade/downgrade paths and in-flight requests.
    # What problems might arise from toggling Google on / off while running?
    # E.g., Our Redis store might have state from the traditional email loop, or
    # vice versa.
    halt 401, 'No continuation available for this user' if data.empty?

    redis.del key

    id_token = build_id_token(email, extract_origin(data['redirect']), data['nonce'])

    return erb :forward, { locals: {
      return_uri: data['redirect'],
      id_token: id_token,
      state: data['state'],
    } }
  end

  def extract_origin(uri)
    u = URI.parse(uri)

    origin = "#{u.scheme}://#{u.host}"
    origin += ":#{u.port}" unless u.port == u.default_port

    origin
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
      iss: "#{settings.scheme}://#{settings.host}",
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
