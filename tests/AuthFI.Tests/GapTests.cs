using System.Numerics;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace AuthFI.Tests;

/// <summary>Tests that close the mutation survivors found in review 1. All must pass on the PR code.</summary>
public class GapTests
{
    private static void RefusedWith(string code, Action act) => Assert.Equal(code, Assert.Throws<AuthFIException>(act).Code);

    [Fact]
    public void G01_typ_at_jwt_is_case_insensitive_in_both_spellings()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        v.Verify(key.Mint(editHeader: h => h["typ"] = "AT+JWT"));
        v.Verify(key.Mint(editHeader: h => h["typ"] = "At+Jwt"));
        v.Verify(key.Mint(editHeader: h => h["typ"] = "Application/AT+JWT"));
    }

    [Fact]
    public void G02_iss_is_compared_exactly()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        RefusedWith("token_issuer_not_accepted", () => v.Verify(key.Mint(editPayload: p => p["iss"] = "https://ACME.authfi.io")));
        RefusedWith("token_issuer_not_accepted", () => v.Verify(key.Mint(editPayload: p => p["iss"] = Claims.Issuer + "/")));
    }

    [Fact]
    public void G03_exp_boundary_is_exact()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier(); // leeway 60
        v.Verify(key.Mint(editPayload: p => p["exp"] = Claims.Now - 59));
        RefusedWith("token_expired", () => v.Verify(key.Mint(editPayload: p => p["exp"] = Claims.Now - 60)));
        var strict = new TestIssuer(key).Verifier(o => o.Leeway = TimeSpan.Zero);
        strict.Verify(key.Mint(editPayload: p => p["exp"] = Claims.Now + 1));
        RefusedWith("token_expired", () => strict.Verify(key.Mint(editPayload: p => p["exp"] = Claims.Now)));
    }

    [Fact]
    public void G04_fractional_exp_rounds_down()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        RefusedWith("token_expired", () => v.Verify(key.Mint(editPayload: p => p["exp"] = (double)(Claims.Now - 60) + 0.5)));
    }

    [Fact]
    public void G05_nbf_and_iat_boundaries_are_exact_and_both_get_leeway()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier(); // leeway 60
        v.Verify(key.Mint(editPayload: p => p["nbf"] = Claims.Now + 60));
        RefusedWith("token_claims_invalid", () => v.Verify(key.Mint(editPayload: p => p["nbf"] = Claims.Now + 61)));
        v.Verify(key.Mint(editPayload: p => p["iat"] = Claims.Now + 60));
        RefusedWith("token_claims_invalid", () => v.Verify(key.Mint(editPayload: p => p["iat"] = Claims.Now + 61)));
        v.Verify(key.Mint(editPayload: p => p["iat"] = Claims.Now + 30)); // inside leeway
    }

    [Fact]
    public void G06_tenant_pin_is_exact()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier(o => o.ExpectedTenantId = Claims.Tenant);
        RefusedWith("token_tenant_not_issuers", () => v.Verify(key.Mint(editPayload: p => p["tenant_id"] = Claims.Tenant.ToUpperInvariant())));
    }

    [Fact]
    public void G07_rsa_keys_below_2048_bits_are_not_published_keys()
    {
        foreach (var bits in new[] { 1024, 2040 })
        {
            var key = TestKey.Create("RS256", "small");
            // Replace the modulus with a `bits`-bit odd number (top bit set); the key cannot sign, so an accepted key shows
            // as token_signature_invalid and a dropped key as token_key_unknown.
            var n = (BigInteger.One << (bits - 1)) | (BigInteger.One << (bits - 2)) | BigInteger.One;
            var bytes = n.ToByteArray(isUnsigned: true, isBigEndian: true);
            key.Jwk["n"] = TestKey.B64u(bytes);
            var v = new TestIssuer(key).Verifier();
            RefusedWith("token_key_unknown", () => v.Verify(key.Mint()));
        }
    }

    [Fact]
    public void G08_a_malformed_token_is_not_echoed_in_the_exception()
    {
        var v = new TestIssuer(TestKey.Create("EdDSA", "k1")).Verifier();
        foreach (var t in new[] { "s3cr3tabc.s3cr3tdef", "s3cr3t", "s3cr3t.s3cr3t.s3cr3t.s3cr3t", ".s3cr3t.s3cr3t" })
        {
            var e = Assert.Throws<AuthFIException>(() => v.Verify(t));
            Assert.DoesNotContain("s3cr3t", e.Message);
            Assert.DoesNotContain("s3cr3t", e.ToString());
        }
    }

    [Fact]
    public void G09_a_token_over_16_KiB_is_refused_as_malformed_before_any_key_fetch()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var v = issuer.Verifier();
        var good = key.Mint(editPayload: p => p["pad"] = new string('a', 17000));
        RefusedWith("token_malformed", () => v.Verify(good));
        Assert.Empty(issuer.Handler.Requests);
    }

    [Fact]
    public void G10_jwks_uri_must_be_https()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var handler = new StubHandler(r => r.RequestUri!.AbsolutePath == "/.well-known/oauth-authorization-server"
            ? new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{\"issuer\":\"https://acme.authfi.io\",\"jwks_uri\":\"http://keys.example.com/jwks\"}", Encoding.UTF8, "application/json")
            }
            : new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent("{\"keys\":[]}") });
        var v = issuer.Verifier(o => o.HttpClient = new HttpClient(handler));
        RefusedWith("jwks_unavailable", () => v.Verify(key.Mint()));
        Assert.Single(handler.Requests); // the jwks_uri itself was never requested
    }

    [Fact]
    public void G11_an_oversized_key_set_is_refused()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var handler = new StubHandler(r => r.RequestUri!.AbsolutePath == "/.well-known/oauth-authorization-server"
            ? new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{\"issuer\":\"https://acme.authfi.io\",\"jwks_uri\":\"https://acme.authfi.io/.well-known/jwks.json\"}")
            }
            : new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{\"keys\":[],\"pad\":\"" + new string('a', 2 * 1024 * 1024) + "\"}")
            });
        var v = issuer.Verifier(o => o.HttpClient = new HttpClient(handler));
        RefusedWith("jwks_unavailable", () => v.Verify(key.Mint()));
    }

    [Fact]
    public void G12_own_audience_refusal_covers_host_case_port_and_scheme()
    {
        foreach (var a in new[] { "https://ACME.authfi.io/mcp", "https://acme.authfi.io:8443/x", "HTTP://acme.authfi.io/y" })
        {
            var o = new AuthFIVerifierOptions { Issuer = "https://acme.authfi.io" };
            o.Audiences.Add(a);
            Assert.Throws<AuthFIConfigurationException>(() => new AuthFIVerifier(o));
        }
    }

    [Fact]
    public void G13_a_DPoP_authorization_scheme_is_refused_as_unsupported()
    {
        var client = new AuthFIClient(new TestIssuer(TestKey.Create("EdDSA", "k1")).Verifier().Issuer, "api_orders");
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization = "DPoP abc.def.ghi";
        Assert.Equal("token_dpop_unsupported", Assert.Throws<AuthFIException>(() => client.Authenticate(ctx)).Code);
        ctx.Request.Headers.Authorization = "Basic abc";
        Assert.Equal("token_missing", Assert.Throws<AuthFIException>(() => client.Authenticate(ctx)).Code);
    }

    [Fact]
    public void G14_a_jwe_is_refused_with_its_own_message()
    {
        var v = new TestIssuer(TestKey.Create("EdDSA", "k1")).Verifier();
        var e = Assert.Throws<AuthFIException>(() => v.Verify("a.b.c.d.e"));
        Assert.Contains("JWE", e.Message);
    }
}
