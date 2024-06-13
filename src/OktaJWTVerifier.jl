module OktaJWTVerifier

using Base64, HTTP2, JSON, Dates, JWTs, ExpiringCaches, Logging

export Verifier, verify_access_token!, verify_id_token!

const regx = r"[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.?([a-zA-Z0-9-_]+)[/a-zA-Z0-9-_]+?$"

function jsonparse(bytes)
    try
        return JSON.parse(String(bytes))
    catch
        throw(ArgumentError("failed to parse JSON"))
    end
end

struct Verifier
    issuer::String
    claims_to_validate::Dict{String, String}
    discovery_well_known_url::String
    jwkset::Union{JWKSet, Nothing}
    jwkset_cache::ExpiringCaches.Cache{String, Any}
    cache::ExpiringCaches.Cache{String, Any}
    metadata_cache::ExpiringCaches.Cache{String, Any}
    leeway::Int64
    timeout::Dates.Minute
    cleanup::Dates.Minute
end

"""
    Verifier(issuer::String;
        claims_to_validate::Dict{String, String} = Dict{String, String}(),
        timeout::Dates.Minute = Dates.Minute(5),
        discovery_well_known_url::String = "/.well-known/openid-configuration",
        cache::Cache = Cache{String, Any}(timeout),
        metadata_cache::Cache = Cache{String, Any}(timeout),
        leeway::Int64 = 120,
        cleanup::Dates.Minute = Dates.Minute(5)
    )

Create a new Verifier for the given issuer. The issuer is the full issuer URL of the
Okta org, e.g. https://dev-123456.okta.com/oauth2/default. The issuer is used to fetch the
metadata for the Okta org, which is cached for the duration of the timeout.

Verifier objects can then be used to verify access tokens and id tokens.
See [`verify_access_token!`](@ref) and [`verify_id_token!`](@ref) for more details.
"""
function Verifier(issuer::String;
    claims_to_validate::Dict{String, String} = Dict{String, String}(),
    timeout::Dates.Minute = Dates.Minute(5),
    discovery_well_known_url::String = ".well-known/openid-configuration",
    cache::Cache = Cache{String, Any}(timeout),
    metadata_cache::Cache = Cache{String, Any}(timeout),
    leeway::Int64 = 120,
    cleanup::Dates.Minute = Dates.Minute(5)
)
    return Verifier(issuer, claims_to_validate, discovery_well_known_url, nothing, Cache{String, Any}(timeout), cache, metadata_cache, leeway, timeout, cleanup)
end

struct Jwt
    claims::Dict{String, Any}
end

# http get to metadata url to get the jwks_uri
function fetch_metadata(url::String)
    local resp
    try
        resp = HTTP2.get(url)
    catch e
        @error "failed to fetch metadata" exception=(e, catch_backtrace())
        throw(ArgumentError("Request for metadata $url was not HTTP2 2xx OK"))
    end
    return jsonparse(resp.body)
end

function get_metadata(j::Verifier)
    metadata_url = joinpath(j.issuer, j.discovery_well_known_url)
    return get!(j.metadata_cache, metadata_url) do
        fetch_metadata(metadata_url)
    end
end

function decode(v::Verifier, jwt::String, jwkuri::String)
    jwkset = get!(v.jwkset_cache, jwkuri) do
        jks = JWKSet(jwkuri)
        refresh!(jks)
        return jks
    end
    token = JWT(; jwt)
    validate!(token, jwkset)
    return claims(token)
end

function decode_jwt(j::Verifier, jwt::String)
    metadata = get_metadata(j)
    jwkuri = get(metadata, "jwks_uri", "")
    jwkuri == "" && throw(ArgumentError("failed to decode JWT: missing 'jwks_uri' from metadata"))
    return decode(j, jwt, jwkuri)
end

"""
    verify_access_token!(j::Verifier, jwt::String)

Verify the given access token using the given Verifier. The Verifier must have been
created with the same issuer as the access token. The access token must be a valid JWT
and must have been issued by the same issuer as the Verifier. The access token must also
be valid according to the claims_to_validate passed to the Verifier constructor.

Returns a Jwt object containing the claims of the access token.
"""
function verify_access_token!(j::Verifier, jwt::String)
    is_valid_jwt(jwt) || throw(ArgumentError("token is not valid: $jwt"))

    myJwt = Jwt(decode_jwt(j, jwt))

    validate_iss!(j, myJwt.claims["iss"])
    validate_audience!(j, myJwt.claims["aud"])
    haskey(myJwt.claims, "cid") && validate_client_id!(j, myJwt.claims["cid"])
    validate_exp!(j, myJwt.claims["exp"])
    validate_iat!(j, myJwt.claims["iat"])
    return myJwt
end

"""
    verify_id_token!(j::Verifier, jwt::String)

Verify the given id token using the given Verifier. The Verifier must have been
created with the same issuer as the id token. The id token must be a valid JWT
and must have been issued by the same issuer as the Verifier. The id token must also
be valid according to the claims_to_validate passed to the Verifier constructor.

Returns a Jwt object containing the claims of the id token.
"""
function verify_id_token!(j::Verifier, jwt::String)
    is_valid_jwt(jwt) || throw(ArgumentError("token is not valid: $jwt"))

    myJwt = Jwt(decode_jwt(j, jwt))

    validate_iss!(j, myJwt.claims["iss"])
    validate_audience!(j, myJwt.claims["aud"])
    validate_client_id!(j, myJwt.claims["cid"])
    validate_exp!(j, myJwt.claims["exp"])
    validate_iat!(j, myJwt.claims["iat"])
    validate_nonce!(j, myJwt.claims["nonce"])
    return myJwt
end

function validate_nonce!(j::Verifier, nonce::String)
    if get(j.claims_to_validate, "nonce", "") != nonce
        throw(ArgumentError("nonce does not match"))
    end
end

function validate_audience!(j::Verifier, aud::Union{String, Vector, Dict})
    if aud isa String
        aud == j.claims_to_validate["aud"] || throw(ArgumentError("audience does not match"))
    elseif aud isa Vector
        any(==(j.claims_to_validate["aud"]), aud) || throw(ArgumentError("audience does not match"))
    elseif aud isa Dict
        any(==(j.claims_to_validate["aud"]), values(aud)) || throw(ArgumentError("audience does not match"))
    else
        throw(ArgumentError("unknown audience type; unable to validate"))
    end
end

function validate_client_id!(j::Verifier, cid::String)
    if haskey(j.claims_to_validate, "cid")
        v = j.claims_to_validate["cid"]
        if v isa String
            v == cid || throw(ArgumentError("client id does not match"))
        elseif v isa Vector
            any(==(cid), v) || throw(ArgumentError("client id does not match"))
        else
            throw(ArgumentError("unknown client id type"))
        end
    end
end

function validate_exp!(j::Verifier, exp::Int64)
    now = Dates.datetime2unix(Dates.now(Dates.UTC) - Dates.Second(j.leeway))
    # if exp is less than [leeway] seconds ago, then it's expired
    exp < now && throw(ArgumentError("token is expired"))
end

function validate_iat!(j::Verifier, iat::Int64)
    now = Dates.datetime2unix(Dates.now(Dates.UTC) + Dates.Second(j.leeway))
    # if iat is greater than [leeway] seconds in the future, then it's invalid
    now < iat && throw(ArgumentError("token issued in the future"))
end

function validate_iss!(j::Verifier, iss::String)
    if iss != j.issuer
        throw(ArgumentError("issuer does not match"))
    end
end

function is_valid_jwt(jwt::String)
    jwt == "" && throw(ArgumentError("token is empty"))
    match(regx, jwt) !== nothing || throw(ArgumentError("token is not valid: $jwt"))
    parts = split(jwt, ".")
    header = jsonparse(base64decode(padheader(String(parts[1]))))
    haskey(header, "alg") || throw(ArgumentError("the tokens header must contain an 'alg'"))
    haskey(header, "kid") || throw(ArgumentError("the tokens header must contain a 'kid'"))
    header["alg"] == "RS256" || throw(ArgumentError("the tokens alg must be 'RS256'"))
    return true
end

function padheader(header::String)::String
    i = length(header) % 4
    if i != 0
        header *= repeat("=", 4 - i)
    end
    return header
end

end
