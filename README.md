# Let's Auth Daemon Prototype: OpenID Connect

Let's Auth is a passwordless login system masquerading as OpenID Connect.

It works like Facebook Connect or Google Login, but for *any* email address.
Best of all, it's self-hostable: your users maintain control of their identity,
and you maintain control of your site's authentication.

Let's Auth exposes a public API that implements the [OpenID Connect
Core][oidc-core] "[Implicit Flow][oidc-implicit]," so it's easy to add to your
website.

                                       Traditional Email   +----------------+
                                     +-------------------> | Email Provider |
                                     | Confirmation Link   +----------------+
                                     |                             /
    +---------+    Open ID    +------------+                      /
    | Website | <-----------> | Let's Auth | <-------------------+
    +---------+    Connect    +------------+                      \
                                     |                             \
                                     | Open ID Connect   +-------------------+
                                     +-----------------> |  OpenID Provider  |
                                       (Unimplemented)   +-------------------+

## HTTP Routes

-   __GET /.well-known/openid-configuration__

    OpenID Provider metadata, compliant with [OpenID Connect Discovery 1.0][oidc-disco].

-   __GET or POST /auth__

    OAuth2 Authorization Endpoint. Location formally defined by
    `authorization_endpoint` in `/.well-known/openid-configuration`.

-   __GET /jwks.json__

    Cryptographic keys used for signing JWTs, serialized as a JWK Set. Location
    formally defined by `jwks_uri` in `/.well-known/openid-configuration`.

-   __GET /confirm__

    Target of email verification links.

## Authenticating Users with Let's Auth

Let's Auth uses OpenID Connect's "[Implicit Flow][oidc-implicit]," please refer
to that specification for additional details. Generally speaking, you'll need to
ask Let's Auth to authenticate a user, then receive and validate the response.

1.  Ask the user for their email address, then send an [Authorization
    Request][oauth2] to `/auth/` with the following parameters:

    - `scope=openid email`
    - `response_type=id_token`
    - `client_id=http://example.com`, where `http://example.com` is your
        website's address, including only the scheme, host, and any non-default
        port. This must match the `Origin` header sent by the user's browser.
    - `redirect_uri=http://example.com/login`, where `http://example.com/login`
        is the full URI where you would like to receive the user's credentials.
        This must have the same scheme, host, and port as the `client_id`.
    - `login_hint=user@example.com`, where `user@example.com` is the email
        address of the user attempting to log into your website.

    You may optionally provide a `nonce`, which will be echoed back unchanged in
    the signed `id_token`, or a `state` parameter, which will be echoed back
    unchanged adjacent to the `id_token` when returning to your `redirect_uri`.

2.  Once Let's Auth authenticates your user, they will be returned to your site,
    and their verified identity will be encoded in a [JWT][jwt-io] called
    `id_token` added to the fragment part of your `redirect_uri`.

    JavaScript on your page must read the fragment, extract the `id_token`,
    and pass it to your backend for validation in a trusted environment.

3.  Your backend should validate the `id_token` by ensuring:

    1. The Issuer (`iss`) and the Audience (`aud`) match Let's Auth and your
       origin, respectively.

    2. The Issued At (`iat`) time is not in the future, and the Expires (`exp`)
       time is not in the past, though you should allow for a few minutes of
       leeway in case of clock differences between your server and the Let's
       Auth server.

    3. The `nonce` value, if you provided one, matches what you provided, and
       has not been previously used during this token's validity period.

    4. The JWT's header specifies an `alg` of `RS256`, and the signature matches
       the key identified by `kid` in the header. The key should be present in
       the JWK Set at `/jwks.json` on the Let's Auth server.

    If successful, you know that the JWT came from Let's Auth, was intended for
    your website, has not expired, was not re-used, and is authentic.

4.  Having determined that the JWT is good, you know that the current user has
    access to the email address specified in the JWT's Subject (`sub`) field,
    and repeated in the `email` and `email_verified` fields. At this point, you
    may use whatever means you'd like to establish the user's session. For
    instance, you may ask their browser to set a secure, signed cookie
    containing their session information.

The OpenID Connect spec has a good [id_token example][id-token-example] which
shows both how it's encoded into the URI fragment, and what its contents look
like once decoded.

## How Let's Auth Confirms Email Addresses

In the future, Let's Auth will automatically select the best possible
authentication strategy for each incoming email address. For instance, Gmail
users may be asked to authenticate through the federated "Sign in with Google"
process, while other users may see a traditional workflow based on email
confirmation links.

At the moment, only the confirmation link workflow has been implemented, so all
users will have the same experience:

1. Let's Auth receives the user's email address and the website's redirect URI
   in the request to `/auth`

2. The backend generates a unique confirmation code for this authentication
   attempt and stores it in Redis alongside the redirect URI. This entry is
   keyed based on the combination of the user's email address and the target
   website's origin. It is configured to expire after several minutes or some
   number of incorrect login attempts.

3. The backend then emails the user a link which has their code, email address,
   and target website embedded in its query parameters.

4. When the user clicks the confirmation link, the backend checks to see if
   there's a pending authentication for the provided combination of user,
   website, and code.

5. If successful, the backend redirects the user to the originating website's
   `redirect_uri`, which was recorded in Redis. It also appends a signed
   `id_token` to the redirect URI's fragment, which attests to the user's
   identity.

## Developing Locally

1. `gem install`
2. `rackup`

Then, use the various endpoints!

Initiate an authentication request:

    curl -i -X POST 127.0.0.1:9292/auth \
        -H 'Origin: https://example.com' \
        -d 'scope=openid%20email' \
        -d 'response_type=id_token' \
        -d 'client_id=https://example.com' \
        -d 'redirect_uri=https://example.com/return' \
        -d 'login_hint=user@example.net' \
        -d 'nonce=OptionalNonce' \
        -d 'state=OptionalState'

Complete an authentication request:

    curl -i '127.0.0.1:9292/confirm?email=user@example.net&origin=https://example.com&code=XXXXXX'

In development mode, the generated emails will be printed to the console where
`rackup` is running.

## Running on Heroku

For prototyping, there are a few hard-coded dependencies on Heroku, primarily
around configuring domain names and email. These will be removed before v1.

To get set up, make sure to run the following commands:

    heroku labs:enable runtime-dyno-metadata
    heroku addons:create heroku-redis:hobby-dev
    heroku addons:create postmark:10k
    heroku config:set LETSAUTH_PRIVATE_KEY='...' # In PEM format

You'll also need to confirm your sending address in the Postmark's settings, and
update the `:from` address in `server.rb` to match.

[jwt-spec]: https://tools.ietf.org/html/rfc7519
[jwt-io]: https://jwt.io
[oauth2]: http://tools.ietf.org/html/rfc6749
[oidc-core]: http://openid.net/specs/openid-connect-core-1_0.html
[oidc-disco]: http://openid.net/specs/openid-connect-discovery-1_0.html
[oidc-implicit]: http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
[id-token-example]: http://openid.net/specs/openid-connect-core-1_0.html#id_tokenExample
[id-token-fragment]: http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#id_token
