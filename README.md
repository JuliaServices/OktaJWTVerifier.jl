# OktaJWTVerifier.jl

> [!IMPORTANT]
> This package is deprecated. New code should use
> [JWTs.jl](https://github.com/JuliaWeb/JWTs.jl) instead.

OktaJWTVerifier.jl was a small Okta-oriented wrapper around JWT verification.
Its functionality now belongs in the provider-neutral
[JWTs.jl](https://github.com/JuliaWeb/JWTs.jl) package, which supports
OpenID Connect discovery, cached remote JWKS endpoints, registered-claim
validation, typed verification errors, and a broader JOSE algorithm set.

This repository is retained for existing users, but new features and normal
maintenance should happen in JWTs.jl. After migrating, depend on `JWTs` directly
instead of `OktaJWTVerifier`.

GitHub Actions : [![Build Status](https://github.com/JuliaServices/OktaJWTVerifier.jl/workflows/CI/badge.svg)](https://github.com/JuliaServices/OktaJWTVerifier.jl/actions?query=workflow%3ACI+branch%3Amain)

[![codecov.io](http://codecov.io/github/JuliaServices/OktaJWTVerifier.jl/coverage.svg?branch=main)](http://codecov.io/github/JuliaServices/OktaJWTVerifier.jl?branch=main)

## Recommended Replacement

Install JWTs.jl:

```julia
import Pkg
Pkg.add("JWTs")
```

Useful JWTs.jl links:

- [JWTs.jl repository](https://github.com/JuliaWeb/JWTs.jl)
- [Verification with claims](https://github.com/JuliaWeb/JWTs.jl#verification-with-claims)
- [OpenID Connect discovery](https://github.com/JuliaWeb/JWTs.jl#openid-connect-discovery)
- [Remote JWKS](https://github.com/JuliaWeb/JWTs.jl#remote-jwks)
- [Migration notes](https://github.com/JuliaWeb/JWTs.jl#migration-notes)
- [JWTs on JuliaHub](https://juliahub.com/ui/Packages/General/JWTs)

## Migration

OktaJWTVerifier.jl:

```julia
using OktaJWTVerifier

issuer = "https://myoktadomain.okta.com/oauth2/default"
audience = "myoktaaudience"

verifier = OktaJWTVerifier.Verifier(
    issuer;
    claims_to_validate=Dict("aud" => audience),
)

jwt = OktaJWTVerifier.verify_access_token!(verifier, token)
claims = jwt.claims
```

JWTs.jl:

```julia
using JWTs

issuer = "https://myoktadomain.okta.com/oauth2/default"
audience = "myoktaaudience"

verifier = JWTs.Verifier(
    issuer;
    algorithms=["RS256"],
    audience=audience,
    leeway=120,
    required_claims=["exp", "iat", "iss", "aud"],
)

verified = JWTs.verify(verifier, token)
claims = JWTs.claims(verified)
```

Important differences:

- JWTs.jl intentionally exports no names. Use the `JWTs.` namespace or import
  the specific names you need.
- `claims_to_validate=Dict("aud" => audience)` maps to `audience=audience`.
- OktaJWTVerifier.jl used a default leeway of 120 seconds. Set `leeway=120` in
  JWTs.jl if you want the same clock-skew behavior.
- OktaJWTVerifier.jl was hard-coded around `RS256`. JWTs.jl requires an
  explicit algorithm allowlist such as `algorithms=["RS256"]`.
- JWTs.jl validates `exp`, `nbf`, and `iat` when present. Add
  `required_claims=["exp", "iat", ...]` when your application requires those
  claims to exist.
- `JWTs.verify` returns a `JWTs.VerifiedJWT`. Use `JWTs.claims(verified)` or
  `verified.claims` to access the decoded claims.

## ID Tokens and Provider-Specific Claims

For ID-token nonce validation, pass `nonce` to `JWTs.Verifier`:

```julia
verifier = JWTs.Verifier(
    issuer;
    algorithms=["RS256"],
    audience=client_id,
    nonce=expected_nonce,
    leeway=120,
    required_claims=["exp", "iat", "iss", "aud", "nonce"],
)

verified = JWTs.verify(verifier, id_token)
claims = JWTs.claims(verified)
```

OktaJWTVerifier.jl also had special handling for the Okta `cid` claim. JWTs.jl
keeps provider-specific policy in application code, so check that claim after
signature and registered-claim verification if your application depends on it:

```julia
claims = JWTs.claims(JWTs.verify(verifier, token))
claims["cid"] == expected_client_id || throw(ArgumentError("client id does not match"))
```

## Downloads and Fetchers

OktaJWTVerifier.jl exposed a package-global `DOWNLOADER`. JWTs.jl takes a
configured downloader directly:

```julia
using Downloads
using JWTs

downloader = Downloads.Downloader(; grace=0)

verifier = JWTs.Verifier(
    issuer;
    algorithms=["RS256"],
    audience=audience,
    downloader=downloader,
)
```

Tests can inject a deterministic fetcher:

```julia
fetcher = url -> read("fixtures/openid-or-jwks.json", String)

verifier = JWTs.Verifier(
    issuer;
    algorithms=["RS256"],
    audience=audience,
    fetcher=fetcher,
)
```

## Historical Usage

Existing OktaJWTVerifier.jl code may continue to look like this:

```julia
using OktaJWTVerifier

v = OktaJWTVerifier.Verifier(
    "https://myoktadomain.okta.com/oauth2/default";
    claims_to_validate=Dict("aud" => "myoktaaudience"),
)

OktaJWTVerifier.verify_access_token!(v, "myoktaaccesstoken")
OktaJWTVerifier.verify_id_token!(v, "myoktaidtoken")
```

Prefer migrating this code to JWTs.jl. The JWTs.jl API is more explicit about
algorithm policy, claim policy, and remote key fetching, and is the canonical
Julia package for JWT verification going forward.
