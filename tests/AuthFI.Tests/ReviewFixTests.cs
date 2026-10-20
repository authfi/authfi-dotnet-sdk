using System.Numerics;
using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace AuthFI.Tests;

/// <summary>One test for each defect the adversarial review found; each fails on the code before its fix.</summary>
public class ReviewFixTests
{
    private static string Code(Action act) => Assert.Throws<AuthFIException>(act).Code;

    private static string DefaultPayload => Claims.Default().ToJsonString();

    private sealed class AsyncOnlyHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
    }

    // F1: unauthenticated input must never raise anything but AuthFIException.
    [Theory]
    [InlineData("{\"alg\":\"EdDSA\",\"typ\":\"at+jwt\",\"kid\":\"\\ud800\"}")]
    [InlineData("{\"alg\":\"\\udc00\",\"typ\":\"at+jwt\",\"kid\":\"k1\"}")]
    [InlineData("{\"alg\":\"EdDSA\",\"typ\":\"\\ud800\",\"kid\":\"k1\"}")]
    public void F1_a_lone_surrogate_in_the_header_is_a_malformed_token(string header)
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        Assert.Equal("token_malformed", Code(() => v.Verify(key.MintRaw(header, DefaultPayload))));
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("tenant_id")]
    [InlineData("email")]
    [InlineData("iss")]
    public void F1_a_lone_surrogate_in_a_signed_claim_is_refused_not_thrown(string claim)
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        var payload = DefaultPayload.Replace($"\"{claim}\":\"", $"\"{claim}\":\"\\ud800");
        var e = Assert.Throws<AuthFIException>(() => v.Verify(key.MintRaw("{\"alg\":\"EdDSA\",\"typ\":\"at+jwt\",\"kid\":\"k1\"}", payload)));
        Assert.StartsWith("token_", e.Code);
    }

    // F2: AuthFI's own domain is never an audience.
    [Theory]
    [InlineData("https://api.authfi.io")]
    [InlineData("https://authfi.io/api")]
    [InlineData("https://something.nonprod.authfi.io")]
    [InlineData("HTTPS://API.AUTHFI.IO")]
    public void F2_AuthFIs_own_domain_cannot_be_an_audience(string audience)
    {
        var o = new AuthFIVerifierOptions { Issuer = "https://acme.example.com" };
        o.Audiences.Add(audience);
        Assert.Throws<AuthFIConfigurationException>(() => new AuthFIVerifier(o));
    }

    [Fact]
    public void F2_a_customers_own_url_is_a_fine_audience()
    {
        var o = new AuthFIVerifierOptions { Issuer = "https://acme.authfi.io" };
        o.Audiences.Add("https://api.acme.com/orders");
        o.Audiences.Add("not-authfi.io.example.com");
        _ = new AuthFIVerifier(o);
    }

    // F3 and F4: a failing issuer is not hammered, and callers share one fetch.
    [Fact]
    public void F3_a_failed_fetch_is_not_retried_for_a_few_seconds()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key) { JwksStatus = 500 };
        var v = issuer.Verifier();
        for (var i = 0; i < 20; i++) Assert.Equal("jwks_unavailable", Code(() => v.Verify(key.Mint())));
        Assert.Equal(2, issuer.Handler.Requests.Count);
        issuer.Clock.Now += TimeSpan.FromSeconds(6);
        issuer.JwksStatus = 200;
        v.Verify(key.Mint());
        Assert.Equal(4, issuer.Handler.Requests.Count);
    }

    [Fact]
    public async Task F3_concurrent_callers_share_one_fetch()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var v = issuer.Verifier(o => o.UnknownKidRefetchInterval = TimeSpan.FromSeconds(30));
        var token = key.Mint();
        await Task.WhenAll(Enumerable.Range(0, 30).Select(i => i % 2 == 0
            ? Task.Run(() => v.Verify(token))
            : Task.Run(async () => await v.VerifyAsync(token))));
        Assert.Equal(2, issuer.Handler.Requests.Count);
    }

    // F5
    [Fact]
    public void F5_a_handler_without_a_synchronous_send_is_a_key_fetch_failure()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier(o => o.HttpClient = new HttpClient(new AsyncOnlyHandler()));
        Assert.Equal("jwks_unavailable", Code(() => v.Verify(key.Mint())));
    }

    [Fact]
    public void F5_a_null_secret_is_a_missing_credential()
    {
        var v = new TestIssuer(TestKey.Create("EdDSA", "k1")).Verifier();
        Assert.Equal("token_missing", Code(() => v.Verify((Secret)null!)));
        Assert.Equal("token_missing", Code(() => v.Verify((string)null!)));
    }

    // F6
    [Fact]
    public void F6_option_values_that_disable_the_cache_or_the_clock_are_refused()
    {
        foreach (var edit in new Action<AuthFIVerifierOptions>[]
        {
            o => o.KeyCacheLifetime = TimeSpan.Zero,
            o => o.KeyCacheLifetime = TimeSpan.FromDays(2),
            o => o.UnknownKidRefetchInterval = TimeSpan.FromSeconds(-1),
            o => o.TimeProvider = null!,
        })
        {
            var o = new AuthFIVerifierOptions { Issuer = Claims.Issuer };
            o.Audiences.Add("api_orders");
            edit(o);
            Assert.Throws<AuthFIConfigurationException>(() => new AuthFIVerifier(o));
        }
    }

    // F7
    [Fact]
    public void F7_a_jwk_member_of_the_wrong_type_makes_the_key_unusable()
    {
        foreach (var member in new[] { "alg", "use", "kid" })
        {
            var key = TestKey.Create("RS256", "k1");
            key.Jwk[member] = 5;
            var v = new TestIssuer(key).Verifier();
            Assert.Equal("token_key_unknown", Code(() => v.Verify(key.Mint())));
        }
    }

    [Fact]
    public void F7_an_rsa_modulus_of_2047_bits_is_refused_and_one_of_2048_is_not()
    {
        foreach (var (bits, usable) in new[] { (2047, false), (2048, true) })
        {
            var key = TestKey.Create("RS256", "k1");
            var n = (BigInteger.One << (bits - 1)) | (BigInteger.One << (bits - 2)) | BigInteger.One;
            key.Jwk["n"] = TestKey.B64u(n.ToByteArray(isUnsigned: true, isBigEndian: true));
            var v = new TestIssuer(key).Verifier();
            // The modulus cannot sign: a usable key shows as a bad signature, an unusable one as an unknown key.
            Assert.Equal(usable ? "token_signature_invalid" : "token_key_unknown", Code(() => v.Verify(key.Mint())));
        }
    }

    // F8: one token, one spelling.
    [Fact]
    public void F8_a_signature_spelled_another_way_is_not_the_same_token()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        var parts = key.Mint().Split('.');
        v.Verify(string.Join('.', parts));
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        var last = parts[2][^1];
        var sibling = alphabet[(alphabet.IndexOf(last) & ~0xF) | (((alphabet.IndexOf(last) & 0xF) + 1) & 0xF)];
        Assert.Equal("token_malformed", Code(() => v.Verify(parts[0] + "." + parts[1] + "." + parts[2][..^1] + sibling)));
        Assert.Equal("token_malformed", Code(() => v.Verify(parts[0] + "." + parts[1] + "." + parts[2] + "==")));
        Assert.Equal("token_malformed", Code(() => v.Verify(parts[0] + "=." + parts[1] + "." + parts[2])));
    }

    // F9: duplicate names are the kind of difference attackers use between parsers.
    [Fact]
    public void F9_a_repeated_name_in_the_payload_or_header_is_refused()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        var header = "{\"alg\":\"EdDSA\",\"typ\":\"at+jwt\",\"kid\":\"k1\"}";
        v.Verify(key.MintRaw(header, DefaultPayload));
        var dupExp = DefaultPayload.TrimEnd('}') + ",\"exp\":1}";
        Assert.Equal("token_malformed", Code(() => v.Verify(key.MintRaw(header, dupExp))));
        Assert.Equal("token_malformed", Code(() => v.Verify(key.MintRaw(header.TrimEnd('}') + ",\"kid\":\"k2\"}", DefaultPayload))));
        // The same name nested is not a repeat.
        v.Verify(key.MintRaw(header, DefaultPayload.TrimEnd('}') + ",\"custom\":{\"exp\":1},\"x\":{\"exp\":2}}"));
    }

    // F10 and F12
    [Theory]
    [InlineData("https://user:pass@acme.authfi.io")]
    [InlineData("https://acme.authfi.io/tenant")]
    public void F10_an_issuer_with_credentials_or_a_path_is_refused(string issuer)
    {
        var o = new AuthFIVerifierOptions { Issuer = issuer };
        o.Audiences.Add("api_orders");
        Assert.Throws<AuthFIConfigurationException>(() => new AuthFIVerifier(o));
    }

    [Fact]
    public void F12_a_jwks_uri_must_use_the_issuers_scheme_even_on_loopback()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var handler = new StubHandler(r => r.RequestUri!.AbsolutePath == "/.well-known/oauth-authorization-server"
            ? new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{\"issuer\":\"https://acme.authfi.io\",\"jwks_uri\":\"http://127.0.0.1:9/jwks\"}")
            }
            : new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent("{\"keys\":[]}") });
        var v = issuer.Verifier(o => o.HttpClient = new HttpClient(handler));
        Assert.Equal("jwks_unavailable", Code(() => v.Verify(key.Mint())));
        Assert.Single(handler.Requests);
    }

    // F11
    [Fact]
    public void F11_a_clock_that_steps_back_does_not_freeze_the_key_cache()
    {
        var old = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(old);
        var v = issuer.Verifier(o => o.UnknownKidRefetchInterval = TimeSpan.FromSeconds(30));
        v.Verify(old.Mint());
        issuer.Clock.Now -= TimeSpan.FromHours(2);
        var fresh = TestKey.Create("EdDSA", "k2");
        issuer.Keys.Add(fresh);
        v.Verify(fresh.Mint(editPayload: p => { p["exp"] = Claims.Now - 7200 + 600; p["iat"] = Claims.Now - 7200; }));
    }

    // F13
    [Fact]
    public void F13_the_debugger_cannot_expand_a_secret()
    {
        var field = typeof(Secret).GetField("_value", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var browsable = field.GetCustomAttribute<System.Diagnostics.DebuggerBrowsableAttribute>();
        Assert.NotNull(browsable);
        Assert.Equal(System.Diagnostics.DebuggerBrowsableState.Never, browsable!.State);
    }
}
