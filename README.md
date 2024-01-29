# OktaJWTVerifier.jl

Simple package for verifying Okta JWTs written in pure Julia.

GitHub Actions : [![Build Status](https://github.com/JuliaServices/OktaJWTVerifier.jl/workflows/CI/badge.svg)](https://github.com/JuliaServices/OktaJWTVerifier.jl/actions?query=workflow%3ACI+branch%3Amain)

[![codecov.io](http://codecov.io/github/JuliaServices/OktaJWTVerifier.jl/coverage.svg?branch=main)](http://codecov.io/github/JuliaServices/OktaJWTVerifier.jl?branch=main)

## Usage

```julia
using OktaJWTVerifier
v = OktaJWTVerifier.Verifier("https://myoktadomain.okta.com/oauth2/default"; claims_to_validate=Dict("aud" => "myoktaaudience"))
verify_access_token!(v, "myoktaaccesstoken")
verify_id_token!(v, "myoktaidtoken")
```
