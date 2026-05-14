using Test, Dates, OktaJWTVerifier, HTTP

function with_metadata_server(f)
    body = """{"jwks_uri":"https://example.com/keys"}"""
    server, port = start_metadata_server(body)
    try
        return f("http://127.0.0.1:$port/.well-known/openid-configuration")
    finally
        close(server)
    end
end

function start_metadata_server(body::String)
    base_port = 20_000 + Int(mod(time_ns(), 30_000))
    for offset in 0:20
        port = 20_000 + Int(mod(base_port + offset, 30_000))
        try
            server = HTTP.serve!(Returns(HTTP.Response(200, body)), "127.0.0.1", port; verbose=false)
            return server, port
        catch e
            e isa Base.IOError || rethrow()
        end
    end
    error("failed to bind metadata test server")
end

@testset "OktaJWTVerifier" begin
    # validate issuer
    v = Verifier("https://golang.oktapreview.com")
    @test_throws ArgumentError OktaJWTVerifier.validate_iss!(v, "test")
    # validate nonce
    v = Verifier("https://golang.oktapreview.com"; claims_to_validate=Dict("nonce" => "abc123"))
    @test_throws ArgumentError OktaJWTVerifier.validate_nonce!(v, "test")
    # validate audience
    v = Verifier("https://golang.oktapreview.com"; claims_to_validate=Dict("aud" => "test"))
    @test_throws ArgumentError OktaJWTVerifier.validate_audience!(v, "test2")
    # validate cid
    v = Verifier("https://golang.oktapreview.com"; claims_to_validate=Dict("cid" => "test"))
    @test_throws ArgumentError OktaJWTVerifier.validate_client_id!(v, "test2")
    # validate iat
    v = Verifier("https://golang.oktapreview.com")
    iat = round(Int, Dates.datetime2unix(Dates.now(Dates.UTC) + Dates.Day(1)))
    @test_throws ArgumentError OktaJWTVerifier.validate_iat!(v, iat)
    # iat within leeway doesn't throw
    iat = round(Int, Dates.datetime2unix(Dates.now(Dates.UTC)))
    @test !OktaJWTVerifier.validate_iat!(v, iat)
    # validate exp
    exp = round(Int, Dates.datetime2unix(Dates.now(Dates.UTC) - Dates.Day(1)))
    @test_throws ArgumentError OktaJWTVerifier.validate_exp!(v, exp)
    # exp within leeway doesn't throw
    exp = round(Int, Dates.datetime2unix(Dates.now(Dates.UTC)))
    @test !OktaJWTVerifier.validate_exp!(v, exp)
    # id token tests
    @test_throws ArgumentError OktaJWTVerifier.verify_id_token!(v, "test")
    @test_throws ArgumentError OktaJWTVerifier.verify_id_token!(v, "123456789.aa.aa")
    @test_throws ArgumentError OktaJWTVerifier.verify_id_token!(v, "aa.aa.aa")
    @test_throws ArgumentError OktaJWTVerifier.verify_id_token!(v, "ew0KICAia2lkIjogImFiYzEyMyIsDQogICJhbmQiOiAidGhpcyINCn0.aa.aa")
    @test_throws ArgumentError OktaJWTVerifier.verify_id_token!(v, "ew0KICAiYWxnIjogIlJTMjU2IiwNCiAgImFuZCI6ICJ0aGlzIg0KfQ.aa.aa")
    @test_throws ArgumentError OktaJWTVerifier.verify_id_token!(v, "ew0KICAia2lkIjogImFiYzEyMyIsDQogICJhbGciOiAiSFMyNTYiDQp9.aa.aa")
    # access token tests
    @test_throws ArgumentError OktaJWTVerifier.verify_access_token!(v, "test")
    @test_throws ArgumentError OktaJWTVerifier.verify_access_token!(v, "123456789.aa.aa")
    @test_throws ArgumentError OktaJWTVerifier.verify_access_token!(v, "aa.aa.aa")
    @test_throws ArgumentError OktaJWTVerifier.verify_access_token!(v, "ew0KICAia2lkIjogImFiYzEyMyIsDQogICJhbmQiOiAidGhpcyINCn0.aa.aa")
    @test_throws ArgumentError OktaJWTVerifier.verify_access_token!(v, "ew0KICAiYWxnIjogIlJTMjU2IiwNCiAgImFuZCI6ICJ0aGlzIg0KfQ.aa.aa")
    @test_throws ArgumentError OktaJWTVerifier.verify_access_token!(v, "ew0KICAia2lkIjogImFiYzEyMyIsDQogICJhbGciOiAiSFMyNTYiDQp9.aa.aa")
    with_metadata_server() do url
        @test OktaJWTVerifier.fetch_metadata(url)["jwks_uri"] == "https://example.com/keys"
    end
end
