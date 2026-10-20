using System.Text.Json.Nodes;
using Xunit;

namespace AuthFI.Tests;

/// <summary>Regression tests for the round-2 review findings R2-1 to R2-4 (probes P1 to P4, P12).</summary>
public class Round2Tests
{
    private static string Code(Action act) => Assert.Throws<AuthFIException>(act).Code;

    private sealed class SlowHandler : DelegatingHandler
    {
        public TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            Started.TrySetResult();
            await Release.Task.WaitAsync(ct);
            return await base.SendAsync(r, ct);
        }
    }

    // R2-1
    [Fact]
    public async Task R21_one_callers_cancellation_does_not_block_the_next_caller()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var slow = new SlowHandler { InnerHandler = issuer.Handler };
        var v = issuer.Verifier(o => o.HttpClient = new HttpClient(slow));
        using var cts = new CancellationTokenSource();
        var first = v.VerifyAsync(new Secret(key.Mint()), cts.Token);
        await slow.Started.Task;
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        slow.Release.TrySetResult();
        Assert.NotNull(await v.VerifyAsync(new Secret(key.Mint())));
    }

    [Fact]
    public async Task R21_a_caller_that_gives_up_waiting_on_the_gate_leaves_it_usable()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var slow = new SlowHandler { InnerHandler = issuer.Handler };
        var v = issuer.Verifier(o => o.HttpClient = new HttpClient(slow));
        var holder = v.VerifyAsync(new Secret(key.Mint()));
        await slow.Started.Task;
        using var cts = new CancellationTokenSource(100);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => v.VerifyAsync(new Secret(key.Mint()), cts.Token));
        slow.Release.TrySetResult();
        await holder;
        await v.VerifyAsync(new Secret(key.Mint()));
    }

    // R2-2
    [Fact]
    public void R22_the_standard_base64_alphabet_is_not_another_spelling_of_the_signature()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        var tried = 0;
        for (var i = 0; i < 400 && tried < 3; i++)
        {
            var parts = key.Mint(editPayload: p => p["jti"] = "x" + Guid.NewGuid()).Split('.');
            if (!parts[2].Contains('-') && !parts[2].Contains('_')) continue;
            tried++;
            Assert.Equal("token_malformed", Code(() => v.Verify(parts[0] + "." + parts[1] + "." + parts[2].Replace('-', '+').Replace('_', '/'))));
        }
        Assert.True(tried > 0, "no signature with - or _ in 400 tries");
    }

    // R2-3
    [Fact]
    public void R23_one_unreadable_jwk_does_not_take_down_the_others()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var handler = new StubHandler(r => r.RequestUri!.AbsolutePath.EndsWith("authorization-server")
            ? new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{\"issuer\":\"" + Claims.Issuer + "\",\"jwks_uri\":\"" + Claims.Issuer + "/j\"}")
            }
            : new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{\"keys\":[{\"kty\":\"OKP\",\"kid\":\"\\ud800\",\"x\":\"AAAA\"}," + key.Jwk.ToJsonString() + "]}")
            });
        new TestIssuer(key).Verifier(o => o.HttpClient = new HttpClient(handler)).Verify(key.Mint());
    }

    // R2-4
    [Fact]
    public void R24_a_jwks_uri_on_another_host_is_refused_even_for_a_loopback_issuer()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var handler = new StubHandler(r => r.RequestUri!.AbsolutePath.EndsWith("authorization-server")
            ? new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{\"issuer\":\"http://localhost:5000\",\"jwks_uri\":\"http://169.254.169.254/jwks\"}")
            }
            : new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent("{\"keys\":[]}") });
        var o = new AuthFIVerifierOptions { Issuer = "http://localhost:5000", HttpClient = new HttpClient(handler) };
        o.Audiences.Add("api_orders");
        var tok = key.Mint(editPayload: p => p["iss"] = "http://localhost:5000");
        Assert.Equal("jwks_unavailable", Code(() => new AuthFIVerifier(o).Verify(tok)));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public void R24_a_jwks_uri_on_another_https_host_is_refused()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var handler = new StubHandler(r => r.RequestUri!.AbsolutePath.EndsWith("authorization-server")
            ? new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{\"issuer\":\"" + Claims.Issuer + "\",\"jwks_uri\":\"https://keys.example.net/jwks\"}")
            }
            : new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent("{\"keys\":[]}") });
        var v = new TestIssuer(key).Verifier(o => o.HttpClient = new HttpClient(handler));
        Assert.Equal("jwks_unavailable", Code(() => v.Verify(key.Mint())));
        Assert.Single(handler.Requests);
    }

    // Closes the declared-alg mutant: a key that declares an algorithm its type cannot sign is not a key.
    [Fact]
    public void A_jwk_that_declares_an_alg_its_key_type_cannot_use_is_dropped()
    {
        var key = TestKey.Create("RS256", "k1");
        key.Jwk["alg"] = "ES256";
        var v = new TestIssuer(key).Verifier();
        Assert.Equal("token_key_unknown", Code(() => v.Verify(key.Mint(editHeader: h => h["alg"] = "ES256"))));
        Assert.Equal("token_key_unknown", Code(() => v.Verify(key.Mint())));
    }

    private sealed class ThrowHandler : HttpMessageHandler
    {
        public Exception E = null!;
        protected override HttpResponseMessage Send(HttpRequestMessage r, CancellationToken ct) => throw E;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct) => throw E;
    }

    [Theory]
    [InlineData("Argument")]
    [InlineData("Format")]
    [InlineData("ObjectDisposed")]
    public async Task Whatever_the_transport_throws_the_caller_sees_one_refusal(string kind)
    {
        Exception e = kind switch { "Argument" => new ArgumentException("x"), "Format" => new FormatException("x"), _ => new ObjectDisposedException("x") };
        var key = TestKey.Create("EdDSA", "k1");
        var token = key.Mint();
        var sync = new TestIssuer(key).Verifier(o => o.HttpClient = new HttpClient(new ThrowHandler { E = e }));
        Assert.Equal("jwks_unavailable", Code(() => sync.Verify(token)));
        var async = new TestIssuer(key).Verifier(o => o.HttpClient = new HttpClient(new ThrowHandler { E = e }));
        Assert.Equal("jwks_unavailable", (await Assert.ThrowsAsync<AuthFIException>(() => async.VerifyAsync(token))).Code);
    }

    [Theory]
    [InlineData("https://api.authfi.io./")]
    [InlineData("https://API.AUTHFI.IO.:443/x")]
    public void A_trailing_dot_does_not_make_AuthFIs_host_a_different_host(string audience)
    {
        var o = new AuthFIVerifierOptions { Issuer = "https://acme.example.com" };
        o.Audiences.Add(audience);
        Assert.Throws<AuthFIConfigurationException>(() => new AuthFIVerifier(o));
    }

    [Fact]
    public void An_issuer_with_an_empty_userinfo_is_refused_too()
    {
        var o = new AuthFIVerifierOptions { Issuer = "https://@acme.authfi.io" };
        o.Audiences.Add("api_orders");
        Assert.Throws<AuthFIConfigurationException>(() => new AuthFIVerifier(o));
    }
}
