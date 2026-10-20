using System.Text.Json.Nodes;
using Xunit;

namespace AuthFI.Tests;

/// <summary>Tests that close the review-2 mutation survivors. All must pass on the PR code (cb3c5e4).</summary>
public class GapTests2
{
    private static string Code(Action act) => Assert.Throws<AuthFIException>(act).Code;
    private const string Hdr = "{\"alg\":\"EdDSA\",\"typ\":\"at+jwt\",\"kid\":\"k1\"}";

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

    // M11
    [Theory]
    [InlineData("https://login.acme.com:8443/x")]
    [InlineData("HTTP://LOGIN.ACME.COM/y")]
    public void H01_a_url_on_a_custom_domain_issuers_host_is_refused(string audience)
    {
        var o = new AuthFIVerifierOptions { Issuer = "https://login.acme.com" };
        o.Audiences.Add(audience);
        Assert.Throws<AuthFIConfigurationException>(() => new AuthFIVerifier(o));
    }

    // M16
    [Fact]
    public void H02_names_that_differ_only_in_case_are_not_a_repeat()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(key).Verifier();
        v.Verify(key.MintRaw(Hdr, Claims.Default().ToJsonString().TrimEnd('}') + ",\"Exp\":1}"));
    }

    // M27
    [Fact]
    public void H03_a_jwks_uri_with_credentials_is_refused_and_never_requested()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var handler = new StubHandler(r => r.RequestUri!.AbsolutePath.EndsWith("authorization-server")
            ? new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            { Content = new StringContent("{\"issuer\":\"" + Claims.Issuer + "\",\"jwks_uri\":\"https://u:p@acme.authfi.io/jwks\"}") }
            : new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent("{\"keys\":[]}") });
        var v = new TestIssuer(key).Verifier(o => o.HttpClient = new HttpClient(handler));
        Assert.Equal("jwks_unavailable", Code(() => v.Verify(key.Mint())));
        Assert.Single(handler.Requests);
    }

    // M31
    [Fact]
    public void H04_after_a_clock_step_back_a_retired_key_stops_verifying()
    {
        var k1 = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(k1);
        var v = issuer.Verifier(o => o.UnknownKidRefetchInterval = TimeSpan.FromSeconds(30));
        v.Verify(k1.Mint());
        issuer.Keys.Clear();
        issuer.Keys.Add(TestKey.Create("EdDSA", "k2"));
        issuer.Clock.Now -= TimeSpan.FromHours(1);
        var t = k1.Mint(editPayload: p => { p["exp"] = Claims.Now - 3600 + 600; p["iat"] = Claims.Now - 3600; });
        Assert.Equal("token_key_unknown", Code(() => v.Verify(t)));
    }

    // M32
    [Fact]
    public void H05_an_attempt_stamped_in_the_future_does_not_freeze_the_unknown_kid_throttle()
    {
        var k1 = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(k1);
        var v = issuer.Verifier(o => o.UnknownKidRefetchInterval = TimeSpan.FromSeconds(30));
        v.Verify(k1.Mint());
        issuer.Clock.Now += TimeSpan.FromSeconds(31);
        issuer.JwksStatus = 500; // the refetch fails, so the key set keeps its old fetch time but the attempt is stamped later
        Assert.Equal("jwks_unavailable", Code(() => v.Verify(k1.Mint(editHeader: h => h["kid"] = "nope"))));
        issuer.JwksStatus = 200;
        issuer.Clock.Now -= TimeSpan.FromSeconds(21); // now 10 s after the first fetch, 21 s before the last attempt
        var k2 = TestKey.Create("EdDSA", "k2");
        issuer.Keys.Add(k2);
        v.Verify(k2.Mint(editPayload: p => { p["iat"] = Claims.Now; }));
    }

    // M36
    [Fact]
    public void H06_a_success_clears_the_failure_back_off_even_with_a_short_cache_lifetime()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key) { JwksStatus = 500 };
        var v = issuer.Verifier(o => o.KeyCacheLifetime = TimeSpan.FromSeconds(1));
        var tok = key.Mint();
        Assert.Equal("jwks_unavailable", Code(() => v.Verify(tok)));
        issuer.Clock.Now += TimeSpan.FromSeconds(6);
        issuer.JwksStatus = 200;
        v.Verify(tok);
        issuer.Clock.Now += TimeSpan.FromSeconds(2); // cache expired, last attempt 2 s ago, and that attempt succeeded
        v.Verify(tok);
    }

    // M38
    [Fact]
    public async Task H07_a_callers_own_cancellation_is_not_reported_as_an_issuer_outage()
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
    }

    // M39
    [Fact]
    public async Task H08_a_caller_waiting_for_the_fetch_gate_can_cancel()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var slow = new SlowHandler { InnerHandler = issuer.Handler };
        var v = issuer.Verifier(o => o.HttpClient = new HttpClient(slow));
        var holder = v.VerifyAsync(new Secret(key.Mint()));
        await slow.Started.Task;
        using var cts = new CancellationTokenSource(100);
        var second = v.VerifyAsync(new Secret(key.Mint()), cts.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await second.WaitAsync(TimeSpan.FromSeconds(5)));
        slow.Release.TrySetResult();
        await holder;
    }

    // M41
    [Fact]
    public void H09_a_loopback_http_issuer_may_not_name_an_https_jwks_uri_either()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var handler = new StubHandler(r => r.RequestUri!.AbsolutePath.EndsWith("authorization-server")
            ? new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            { Content = new StringContent("{\"issuer\":\"http://localhost:5000\",\"jwks_uri\":\"https://keys.example.com/jwks\"}") }
            : new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent("{\"keys\":[]}") });
        var o = new AuthFIVerifierOptions { Issuer = "http://localhost:5000", HttpClient = new HttpClient(handler) };
        o.Audiences.Add("api_orders");
        var v = new AuthFIVerifier(o);
        var tok = key.Mint(editPayload: p => p["iss"] = "http://localhost:5000");
        Assert.Equal("jwks_unavailable", Code(() => v.Verify(tok)));
        Assert.Single(handler.Requests);
    }

    // M42
    [Fact]
    public void H10_the_cache_expires_exactly_at_its_lifetime()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var v = issuer.Verifier(o => o.KeyCacheLifetime = TimeSpan.FromMinutes(5));
        var tok = key.Mint();
        v.Verify(tok);
        Assert.Equal(2, issuer.Handler.Requests.Count);
        issuer.Clock.Now += TimeSpan.FromMinutes(5) - TimeSpan.FromMilliseconds(1);
        v.Verify(tok);
        Assert.Equal(2, issuer.Handler.Requests.Count);
        issuer.Clock.Now += TimeSpan.FromMilliseconds(1);
        v.Verify(tok);
        Assert.Equal(4, issuer.Handler.Requests.Count);
    }

    // M43
    [Fact]
    public void H11_the_failure_back_off_ends_exactly_after_five_seconds()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key) { JwksStatus = 500 };
        var v = issuer.Verifier();
        var tok = key.Mint();
        Code(() => v.Verify(tok));
        issuer.Clock.Now += TimeSpan.FromSeconds(5) - TimeSpan.FromMilliseconds(1);
        Code(() => v.Verify(tok));
        Assert.Equal(2, issuer.Handler.Requests.Count);
        issuer.Clock.Now += TimeSpan.FromMilliseconds(1);
        Code(() => v.Verify(tok));
        Assert.Equal(4, issuer.Handler.Requests.Count);
    }
}
