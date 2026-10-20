using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace AuthFI.Tests;

public class VerifierTests
{
    private static readonly string[] Algs = { "RS256", "PS256", "ES256", "EdDSA" };
    public static IEnumerable<object[]> AllAlgs => Algs.Select(a => new object[] { a });

    private static AuthFIException Refused(Action act) => Assert.Throws<AuthFIException>(act);

    private static void RefusedWith(string code, Action act) => Assert.Equal(code, Refused(act).Code);

    // ---- accepted ----

    [Theory, MemberData(nameof(AllAlgs))]
    public void Accepts_a_valid_token_of_every_algorithm(string alg)
    {
        var key = TestKey.Create(alg, "k1");
        var v = new TestIssuer(key).Verifier();
        var c = v.Verify(key.Mint());
        Assert.Equal("user:alice@example.com", c.Sub);
        Assert.Equal(Claims.Tenant, c.TenantId);
        Assert.Equal(new[] { "api_orders" }, c.Audience);
        Assert.Equal(new[] { "read:users" }, c.Permissions);
        Assert.Equal(new[] { "admin" }, c.Roles);
    }

    [Theory, MemberData(nameof(AllAlgs))]
    public async Task Async_path_accepts_and_refuses_like_the_sync_path(string alg)
    {
        var key = TestKey.Create(alg, "k1");
        var v = new TestIssuer(key).Verifier();
        Assert.Equal("user:alice@example.com", (await v.VerifyAsync(key.Mint())).Sub);
        var bad = key.Mint(editHeader: h => h["typ"] = "JWT");
        var e = await Assert.ThrowsAsync<AuthFIException>(() => v.VerifyAsync(bad));
        Assert.Equal("token_not_access_token", e.Code);
    }

    [Fact]
    public void Accepts_the_application_at_jwt_typ_in_any_case()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        v.Verify(key.Mint(editHeader: h => h["typ"] = "Application/AT+JWT"));
    }

    [Fact]
    public void Accepts_a_key_that_declares_no_alg_by_its_key_type()
    {
        var key = TestKey.Create("EdDSA", "k1", declareAlg: false);
        new TestIssuer(key).Verifier().Verify(key.Mint());
    }

    [Fact]
    public void Accepts_one_of_several_audiences_and_a_list_aud()
    {
        var key = TestKey.Create("RS256", "k1");
        var v = new TestIssuer(key).Verifier();
        v.Verify(key.Mint(editPayload: p => p["aud"] = new JsonArray("other", "api_orders")));
    }

    [Fact]
    public void Reads_the_actor_scopes_and_custom_org()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        var c = v.Verify(key.Mint(editPayload: p =>
        {
            p["act"] = new JsonObject { ["sub"] = "agent:agt_1" };
            p["scope"] = "mcp:call model:use";
            p["custom"] = new JsonObject { ["org_id"] = "org_9" };
        }));
        Assert.Equal("agent:agt_1", c.Actor);
        Assert.Equal(new[] { "mcp:call", "model:use" }, c.Scopes);
        Assert.Equal("org_9", c.OrgId);
    }

    // ---- the ID token and other wrong kinds ----

    [Fact]
    public void Refuses_an_id_token_offered_as_an_access_token()
    {
        var key = TestKey.Create("RS256", "k1");
        var v = new TestIssuer(key).Verifier();
        var idToken = key.Mint(editHeader: h => h["typ"] = "JWT",
            editPayload: p => { p["aud"] = "api_orders"; p["nonce"] = "n"; p["at_hash"] = "x"; });
        RefusedWith("token_not_access_token", () => v.Verify(idToken));
    }

    [Fact]
    public void Refuses_a_token_with_no_typ()
    {
        var key = TestKey.Create("RS256", "k1");
        var v = new TestIssuer(key).Verifier();
        RefusedWith("token_not_access_token", () => v.Verify(key.Mint(editHeader: h => h.Remove("typ"))));
    }

    // ---- algorithms ----

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("HS512")]
    [InlineData("RS512")]
    [InlineData("ES384")]
    [InlineData("rs256")]
    public void Refuses_every_other_algorithm_before_any_key_lookup(string alg)
    {
        var key = TestKey.Create("RS256", "k1");
        var issuer = new TestIssuer(key);
        var v = issuer.Verifier();
        RefusedWith("token_signature_invalid", () => v.Verify(key.Mint(editHeader: h => h["alg"] = alg)));
        Assert.Empty(issuer.Handler.Requests);
    }

    [Fact]
    public void Refuses_an_hs256_token_signed_with_the_public_key_material()
    {
        var key = TestKey.Create("RS256", "k1");
        var v = new TestIssuer(key).Verifier();
        var h = TestKey.B64u(Encoding.UTF8.GetBytes("""{"alg":"HS256","typ":"at+jwt","kid":"k1"}"""));
        var p = TestKey.B64u(Encoding.UTF8.GetBytes(Claims.Default().ToJsonString()));
        using var mac = new System.Security.Cryptography.HMACSHA256(Convert.FromBase64String(
            key.Jwk["n"]!.GetValue<string>().Replace('-', '+').Replace('_', '/') + "=="));
        var sig = TestKey.B64u(mac.ComputeHash(Encoding.ASCII.GetBytes(h + "." + p)));
        RefusedWith("token_signature_invalid", () => v.Verify(h + "." + p + "." + sig));
    }

    [Fact]
    public void Refuses_an_alg_that_does_not_fit_the_key_named_by_kid()
    {
        var ed = TestKey.Create("EdDSA", "k1");
        var rsa = TestKey.Create("RS256", "k1");
        var v = new TestIssuer(ed).Verifier();
        // Signed with an RSA key, claiming to be the published EdDSA key's kid, under RS256.
        RefusedWith("token_key_unknown", () => v.Verify(rsa.Mint()));
    }

    [Fact]
    public void A_key_that_declares_an_alg_is_not_used_for_another()
    {
        var key = TestKey.Create("RS256", "k1"); // declares RS256
        var v = new TestIssuer(key).Verifier();
        var forged = key.Mint(editHeader: h => h["alg"] = "PS256"); // PKCS1 signature under PS256
        RefusedWith("token_key_unknown", () => v.Verify(forged));
    }

    // ---- signature ----

    [Theory, MemberData(nameof(AllAlgs))]
    public void Refuses_a_token_signed_by_another_key_with_the_same_kid(string alg)
    {
        var published = TestKey.Create(alg, "k1");
        var attacker = TestKey.Create(alg, "k1");
        var v = new TestIssuer(published).Verifier();
        RefusedWith("token_signature_invalid", () => v.Verify(attacker.Mint()));
    }

    [Fact]
    public void Refuses_a_tampered_payload()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        var parts = key.Mint().Split('.');
        var evil = Claims.Default();
        evil["permissions"] = new JsonArray("admin:everything");
        parts[1] = TestKey.B64u(Encoding.UTF8.GetBytes(evil.ToJsonString()));
        RefusedWith("token_signature_invalid", () => v.Verify(string.Join('.', parts)));
    }

    [Fact]
    public void Refuses_a_truncated_or_empty_signature()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        var parts = key.Mint().Split('.');
        RefusedWith("token_signature_invalid", () => v.Verify(parts[0] + "." + parts[1] + "." + TestKey.B64u(new byte[10])));
        RefusedWith("token_malformed", () => v.Verify(parts[0] + "." + parts[1]));
    }

    // ---- header ----

    [Fact]
    public void Refuses_a_token_with_no_kid()
    {
        var key = TestKey.Create("RS256", "k1");
        var v = new TestIssuer(key).Verifier();
        RefusedWith("token_key_unknown", () => v.Verify(key.Mint(editHeader: h => h.Remove("kid"))));
    }

    [Fact]
    public void Refuses_a_critical_extension_it_does_not_know()
    {
        var key = TestKey.Create("RS256", "k1");
        var v = new TestIssuer(key).Verifier();
        RefusedWith("token_claims_invalid", () => v.Verify(key.Mint(editHeader: h => h["crit"] = new JsonArray("exp"))));
    }

    [Fact]
    public void Never_takes_a_key_from_the_token_itself()
    {
        var published = TestKey.Create("EdDSA", "k1");
        var attacker = TestKey.Create("EdDSA", "evil");
        var issuer = new TestIssuer(published);
        var v = issuer.Verifier();
        var t = attacker.Mint(editHeader: h =>
        {
            h["jwk"] = JsonNode.Parse(attacker.Jwk.ToJsonString());
            h["jku"] = "https://evil.example/jwks";
        });
        RefusedWith("token_key_unknown", () => v.Verify(t));
        Assert.DoesNotContain(issuer.Handler.Requests, r => r.Contains("evil"));
    }

    [Fact]
    public void Refuses_a_jwe_and_a_non_jws()
    {
        var v = new TestIssuer(TestKey.Create("RS256", "k1")).Verifier();
        RefusedWith("token_malformed", () => v.Verify("a.b.c.d.e"));
        RefusedWith("token_malformed", () => v.Verify("only.two"));
        RefusedWith("token_malformed", () => v.Verify("!!!.!!!.!!!"));
        RefusedWith("token_missing", () => v.Verify(""));
        RefusedWith("token_malformed", () => v.Verify(new string('a', 17 * 1024)));
    }

    // ---- claims ----

    [Fact]
    public void Refuses_a_token_from_another_issuer()
    {
        var key = TestKey.Create("RS256", "k1");
        var v = new TestIssuer(key).Verifier();
        RefusedWith("token_issuer_not_accepted", () => v.Verify(key.Mint(editPayload: p => p["iss"] = "https://evil.authfi.io")));
        RefusedWith("token_issuer_not_accepted", () => v.Verify(key.Mint(editPayload: p => p.Remove("iss"))));
        RefusedWith("token_issuer_not_accepted", () => v.Verify(key.Mint(editPayload: p => p["iss"] = Claims.Issuer + "/")));
    }

    [Fact]
    public void Refuses_a_token_for_another_audience_or_none()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        RefusedWith("token_audience_mismatch", () => v.Verify(key.Mint(editPayload: p => p["aud"] = "api_billing")));
        RefusedWith("token_audience_mismatch", () => v.Verify(key.Mint(editPayload: p => p["aud"] = new JsonArray("x", "y"))));
        RefusedWith("token_audience_mismatch", () => v.Verify(key.Mint(editPayload: p => p.Remove("aud"))));
        RefusedWith("token_audience_mismatch", () => v.Verify(key.Mint(editPayload: p => p["aud"] = "API_ORDERS")));
    }

    [Fact]
    public void Enforces_exp_with_leeway_and_requires_it()
    {
        var key = TestKey.Create("RS256", "k1");
        var issuer = new TestIssuer(key);
        var v = issuer.Verifier();
        v.Verify(key.Mint(editPayload: p => p["exp"] = Claims.Now - 30)); // inside the 60 s leeway
        RefusedWith("token_expired", () => v.Verify(key.Mint(editPayload: p => p["exp"] = Claims.Now - 61)));
        RefusedWith("token_claims_invalid", () => v.Verify(key.Mint(editPayload: p => p.Remove("exp"))));
        RefusedWith("token_claims_invalid", () => v.Verify(key.Mint(editPayload: p => p["exp"] = "soon")));
        var strict = issuer.Verifier(o => o.Leeway = TimeSpan.Zero);
        RefusedWith("token_expired", () => strict.Verify(key.Mint(editPayload: p => p["exp"] = Claims.Now - 1)));
    }

    [Fact]
    public void Enforces_nbf_and_iat()
    {
        var key = TestKey.Create("RS256", "k1");
        var v = new TestIssuer(key).Verifier();
        v.Verify(key.Mint(editPayload: p => p["nbf"] = Claims.Now + 30));
        RefusedWith("token_claims_invalid", () => v.Verify(key.Mint(editPayload: p => p["nbf"] = Claims.Now + 61)));
        RefusedWith("token_claims_invalid", () => v.Verify(key.Mint(editPayload: p => p["iat"] = Claims.Now + 61)));
    }

    [Fact]
    public void Requires_sub_and_tenant_and_pins_the_tenant_when_asked()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var v = issuer.Verifier();
        RefusedWith("token_claims_invalid", () => v.Verify(key.Mint(editPayload: p => p.Remove("sub"))));
        RefusedWith("token_no_tenant", () => v.Verify(key.Mint(editPayload: p => p.Remove("tenant_id"))));
        var pinned = issuer.Verifier(o => o.ExpectedTenantId = Claims.Tenant);
        pinned.Verify(key.Mint());
        RefusedWith("token_tenant_not_issuers", () => pinned.Verify(key.Mint(editPayload: p => p["tenant_id"] = "other")));
    }

    [Fact]
    public void Refuses_a_bound_token_and_an_actor_chain_as_bearer()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        RefusedWith("token_dpop_proof_required", () => v.Verify(key.Mint(editPayload: p => p["cnf"] = new JsonObject { ["jkt"] = "x" })));
        RefusedWith("token_dpop_proof_required", () => v.Verify(key.Mint(editPayload: p => p["authfi_mandate"] = "m")));
        RefusedWith("token_act_chain_unsupported", () => v.Verify(key.Mint(editPayload: p =>
            p["act"] = new JsonObject { ["sub"] = "a", ["act"] = new JsonObject { ["sub"] = "b" } })));
    }

    [Fact]
    public void Refuses_malformed_list_claims_instead_of_ignoring_them()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        RefusedWith("token_claims_invalid", () => v.Verify(key.Mint(editPayload: p => p["permissions"] = "read:users")));
        RefusedWith("token_claims_invalid", () => v.Verify(key.Mint(editPayload: p => p["roles"] = new JsonArray(1))));
    }

    // ---- key discovery and rotation ----

    [Fact]
    public void Fetches_keys_once_and_caches_them()
    {
        var key = TestKey.Create("RS256", "k1");
        var issuer = new TestIssuer(key);
        var v = issuer.Verifier();
        for (var i = 0; i < 5; i++) v.Verify(key.Mint());
        Assert.Equal(2, issuer.Handler.Requests.Count); // discovery + jwks
    }

    [Fact]
    public void Refetches_once_on_an_unknown_kid_and_accepts_the_rotated_key()
    {
        var old = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(old);
        var v = issuer.Verifier();
        v.Verify(old.Mint());
        var fresh = TestKey.Create("EdDSA", "k2");
        issuer.Keys.Add(fresh);
        v.Verify(fresh.Mint());
        Assert.Equal(4, issuer.Handler.Requests.Count);
    }

    [Fact]
    public void An_unknown_kid_is_refused_after_one_refetch()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var v = issuer.Verifier();
        var stranger = TestKey.Create("EdDSA", "nope");
        RefusedWith("token_key_unknown", () => v.Verify(stranger.Mint()));
        Assert.Equal(2, issuer.Handler.Requests.Count);
    }

    [Fact]
    public void Random_kids_cannot_drive_the_key_endpoint_faster_than_the_interval()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var v = issuer.Verifier(o => o.UnknownKidRefetchInterval = TimeSpan.FromSeconds(30));
        v.Verify(key.Mint());
        for (var i = 0; i < 20; i++)
            RefusedWith("token_key_unknown", () => v.Verify(TestKey.Create("EdDSA", "r" + i).Mint()));
        Assert.Equal(2, issuer.Handler.Requests.Count);
        issuer.Clock.Now += TimeSpan.FromSeconds(31);
        RefusedWith("token_key_unknown", () => v.Verify(TestKey.Create("EdDSA", "late").Mint(editPayload: p => p["exp"] = Claims.Now + 600)));
        Assert.Equal(4, issuer.Handler.Requests.Count);
    }

    [Fact]
    public void Fetches_again_after_the_cache_lifetime()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var v = issuer.Verifier(o => o.KeyCacheLifetime = TimeSpan.FromMinutes(5));
        v.Verify(key.Mint());
        issuer.Clock.Now += TimeSpan.FromMinutes(4);
        v.Verify(key.Mint(editPayload: p => p["exp"] = Claims.Now + 3600));
        Assert.Equal(2, issuer.Handler.Requests.Count);
        issuer.Clock.Now += TimeSpan.FromMinutes(2);
        v.Verify(key.Mint(editPayload: p => p["exp"] = Claims.Now + 3600));
        Assert.Equal(4, issuer.Handler.Requests.Count);
    }

    [Fact]
    public void A_retired_key_stops_verifying_once_the_set_is_refetched()
    {
        var old = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(old, TestKey.Create("EdDSA", "k2"));
        var v = issuer.Verifier(o => o.KeyCacheLifetime = TimeSpan.FromMinutes(5));
        v.Verify(old.Mint());
        issuer.Keys.RemoveAt(0);
        issuer.Clock.Now += TimeSpan.FromMinutes(6);
        RefusedWith("token_key_unknown", () => v.Verify(old.Mint(editPayload: p => p["exp"] = Claims.Now + 3600)));
    }

    [Fact]
    public void Fails_closed_when_the_keys_cannot_be_fetched()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key) { JwksStatus = 500 };
        var e = Refused(() => issuer.Verifier().Verify(key.Mint()));
        Assert.Equal("jwks_unavailable", e.Code);
        Assert.Equal(503, e.Status);
    }

    [Fact]
    public void Refuses_discovery_that_names_another_issuer()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key) { MetadataIssuer = "https://evil.authfi.io" };
        RefusedWith("jwks_unavailable", () => issuer.Verifier().Verify(key.Mint()));
    }

    [Fact]
    public void Drops_a_kid_published_twice()
    {
        var a = TestKey.Create("EdDSA", "dup");
        var b = TestKey.Create("EdDSA", "dup");
        var v = new TestIssuer(a, b).Verifier();
        RefusedWith("token_key_unknown", () => v.Verify(a.Mint()));
    }

    [Fact]
    public void Skips_keys_it_cannot_use_and_keeps_the_rest()
    {
        var good = TestKey.Create("EdDSA", "good");
        var weak = TestKey.Create("RS256", "weak");
        var issuer = new TestIssuer(weak, good);
        weak.Jwk["use"] = "enc";
        var v = issuer.Verifier();
        v.Verify(good.Mint());
        RefusedWith("token_key_unknown", () => v.Verify(weak.Mint()));
    }

    // ---- configuration ----

    [Fact]
    public void Requires_an_audience()
    {
        var o = new AuthFIVerifierOptions { Issuer = Claims.Issuer };
        Assert.Throws<AuthFIConfigurationException>(() => new AuthFIVerifier(o));
    }

    [Theory]
    [InlineData("https://acme.authfi.io")]
    [InlineData("https://acme.authfi.io/")]
    [InlineData("https://acme.authfi.io/mcp")]
    [InlineData("https://acme.authfi.io/apis/regional/v1")]
    [InlineData("authfi-console")]
    [InlineData("AuthFI-Workspace")]
    [InlineData("")]
    public void Refuses_audiences_that_are_AuthFIs_own(string audience)
    {
        var o = new AuthFIVerifierOptions { Issuer = Claims.Issuer };
        o.Audiences.Add(audience);
        Assert.Throws<AuthFIConfigurationException>(() => new AuthFIVerifier(o));
    }

    [Theory]
    [InlineData("")]
    [InlineData("acme")]
    [InlineData("http://acme.authfi.io")]
    [InlineData("https://acme.authfi.io?x=1")]
    public void Refuses_an_unusable_issuer(string issuer)
    {
        var o = new AuthFIVerifierOptions { Issuer = issuer };
        o.Audiences.Add("api_orders");
        Assert.Throws<AuthFIConfigurationException>(() => new AuthFIVerifier(o));
    }

    [Fact]
    public void Refuses_leeway_outside_zero_to_300_seconds()
    {
        foreach (var s in new[] { -1, 301 })
        {
            var o = new AuthFIVerifierOptions { Issuer = Claims.Issuer, Leeway = TimeSpan.FromSeconds(s) };
            o.Audiences.Add("api_orders");
            Assert.Throws<AuthFIConfigurationException>(() => new AuthFIVerifier(o));
        }
    }

    [Fact]
    public void The_client_verifies_through_the_same_verifier()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var o = new AuthFIVerifierOptions { Issuer = Claims.Issuer, HttpClient = new HttpClient(issuer.Handler), TimeProvider = issuer.Clock };
        o.Audiences.Add("api_orders");
        var client = new AuthFIClient(o);
        var claims = client.VerifyToken(key.Mint());
        client.RequirePermissions(claims, "read:users");
        Assert.Equal(403, Assert.Throws<AuthFIException>(() => client.RequirePermissions(claims, "write:users")).Status);
        client.RequireRole(claims, "admin");
        Assert.Equal(403, Assert.Throws<AuthFIException>(() => client.RequireRole(claims, "owner")).Status);
    }
}
