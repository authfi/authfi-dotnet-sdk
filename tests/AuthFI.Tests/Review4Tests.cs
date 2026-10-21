using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using AuthFI.Agents;
using Xunit;

namespace AuthFI.Tests;

/// <summary>Round-2 review: tests for the changed lines that the author's suite does not pin. All pass on the reviewed code.</summary>
public class Rev5Tests
{
    private static AgentAuth AuthOver(AgentIssuer issuer, Func<HttpRequestMessage, HttpResponseMessage?> over, Action<HttpClient>? edit = null)
    {
        var c = new HttpClient(new StubHandler(r => over(r) ?? issuer.Handler.Respond(r)));
        edit?.Invoke(c);
        return issuer.Auth(o => o.HttpClient = c);
    }

    // ---- origin (observed through approval_url, which uses the same rule) ----

    [Theory]
    [InlineData("https://acme.authfi.io/a", true)]
    [InlineData("https://ACME.authfi.io/a", true)]
    [InlineData("https://acme.authfi.io:443/a", true)]
    [InlineData("https://acme.authfi.io:8443/a", false)]
    [InlineData("http://acme.authfi.io/a", false)]
    [InlineData("http://acme.authfi.io:443/a", false)]
    [InlineData("https://acme.authfi.io./a", false)]
    [InlineData("https://acme.authfi.io@evil.example/a", false)]
    [InlineData("https://acme.authfi.io:443@evil.example/a", false)]
    [InlineData("https://evil.example/a", false)]
    [InlineData("https://sub.acme.authfi.io/a", false)]
    public async Task The_origin_rule_compares_scheme_host_and_port(string url, bool kept)
    {
        var issuer = new AgentIssuer { OnCiba = _ => AgentIssuer.Json(new { auth_req_id = "r", expires_in = 300, approval_url = url }) };
        var got = (await issuer.Auth().BackchannelAuthorizeAsync("a@b.c", "m")).ApprovalUrl;
        Assert.Equal(kept, got is not null);
    }

    [Fact]
    public void An_http_loopback_issuer_takes_only_its_own_http_origin()
    {
        // an issuer with credentials in its URL is refused; a plain loopback issuer is allowed
        Assert.Throws<AuthFIConfigurationException>(() => new AgentAuth(new AgentAuthOptions { Issuer = "https://acme.authfi.io/x@y", AgentId = "a", Key = AgentKey.Generate("EdDSA") }));
        var ok = new AgentAuth(new AgentAuthOptions { Issuer = "http://localhost:5000", AgentId = "a", Key = AgentKey.Generate("EdDSA") });
        Assert.NotNull(ok);
    }

    // ---- poll gate ----

    private sealed class Gated : HttpMessageHandler
    {
        public TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public HttpMessageInvoker Inner = null!;
        public int Polls;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            if (r.Method == HttpMethod.Post && (await r.Content!.ReadAsStringAsync(ct)).Contains("ciba")) { Interlocked.Increment(ref Polls); await Release.Task; }
            return await Inner.SendAsync(r, ct);
        }
    }

    [Fact]
    public async Task A_second_poll_returns_at_once_while_the_first_is_still_in_flight()
    {
        var issuer = new AgentIssuer { OnCibaPoll = _ => AgentIssuer.OAuthError("authorization_pending") };
        var gated = new Gated { Inner = new HttpMessageInvoker(issuer.Handler) };
        var auth = issuer.Auth(o => o.HttpClient = new HttpClient(gated));
        var req = await auth.BackchannelAuthorizeAsync("a@b.c", "m");
        issuer.Clock.Now += TimeSpan.FromSeconds(6);
        var first = auth.PollAsync(req);
        while (gated.Polls == 0) await Task.Delay(5);
        var second = auth.PollAsync(req);
        Assert.True(second.Wait(2000), "the second poll must not wait for the first");
        Assert.Null(second.Result);
        gated.Release.SetResult();
        Assert.Null(await first);
    }

    [Theory]
    [InlineData("authorization_pending")]
    [InlineData("access_denied")]
    public async Task A_poll_that_ends_in_any_way_frees_the_gate_for_the_next(string error)
    {
        var polls = 0;
        var issuer = new AgentIssuer { OnCibaPoll = _ => ++polls == 1 ? AgentIssuer.OAuthError(error) : AgentIssuer.OAuthError("authorization_pending") };
        var auth = issuer.Auth();
        var req = await auth.BackchannelAuthorizeAsync("a@b.c", "m");
        issuer.Clock.Now += TimeSpan.FromSeconds(6);
        try { await auth.PollAsync(req); } catch (AuthFIException) { }
        issuer.Clock.Now += TimeSpan.FromSeconds(6);
        await auth.PollAsync(req);
        Assert.Equal(2, polls); // the second poll was sent, not skipped as "in flight"
    }

    [Fact]
    public async Task A_cancelled_caller_leaves_the_gate_free()
    {
        var polls = 0;
        var issuer = new AgentIssuer { OnCibaPoll = _ => { polls++; return AgentIssuer.OAuthError("authorization_pending"); } };
        var auth = issuer.Auth();
        var req = await auth.BackchannelAuthorizeAsync("a@b.c", "m");
        issuer.Clock.Now += TimeSpan.FromSeconds(6);
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => auth.PollAsync(req, null, cts.Token));
        await auth.PollAsync(req);
        Assert.Equal(1, polls);
    }

    // ---- bounded read ----

    private static HttpResponseMessage JsonOfLength(int bytes)
    {
        var head = "{\"access_token\":\"tok\",\"expires_in\":900,\"pad\":\"";
        var body = head + new string('a', bytes - head.Length - 2) + "\"}";
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, new UTF8Encoding(false), "application/json") };
    }

    [Fact]
    public async Task An_answer_of_exactly_a_megabyte_is_read_and_one_byte_more_is_not()
    {
        Assert.NotNull(await new AgentIssuer { OnMint = _ => JsonOfLength(1 << 20) }.Auth().GetTokenAsync());
        var e = await Assert.ThrowsAsync<AuthFIException>(() => new AgentIssuer { OnMint = _ => JsonOfLength((1 << 20) + 1) }.Auth().GetTokenAsync());
        Assert.Equal("connection_failed", e.Code);
    }

    [Fact]
    public async Task A_declared_length_over_a_megabyte_is_refused_whatever_the_body()
    {
        var issuer = new AgentIssuer
        {
            OnMint = _ =>
            {
                var res = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"access_token\":\"t\",\"expires_in\":900}") };
                res.Content.Headers.ContentLength = 5 << 20;
                return res;
            },
        };
        Assert.Equal("connection_failed", (await Assert.ThrowsAsync<AuthFIException>(() => issuer.Auth().GetTokenAsync())).Code);
    }

    private sealed class NoLengthContent : HttpContent
    {
        private readonly byte[] _b; public NoLengthContent(byte[] b) { _b = b; }
        protected override Task SerializeToStreamAsync(Stream s, TransportContext? c) => s.WriteAsync(_b, 0, _b.Length);
        protected override bool TryComputeLength(out long length) { length = -1; return false; }
    }

    [Fact]
    public async Task An_answer_of_unknown_length_over_a_megabyte_is_refused()
    {
        var head = "{\"access_token\":\"tok\",\"expires_in\":900,\"pad\":\"";
        var body = Encoding.UTF8.GetBytes(head + new string((char)97, (1 << 20) + 1 - head.Length - 2) + "\"}");
        var issuer = new AgentIssuer { OnMint = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new NoLengthContent(body) } };
        Assert.Equal("connection_failed", (await Assert.ThrowsAsync<AuthFIException>(() => issuer.Auth().GetTokenAsync())).Code);
    }

    // ---- timeouts on every path ----

    private static readonly Func<HttpRequestMessage, string, bool> Is = (r, p) => r.RequestUri!.AbsolutePath == p;

    [Theory]
    [InlineData("/.well-known/oauth-authorization-server", "mint")]
    [InlineData("/.well-known/agent-configuration", "approval")]
    [InlineData("/apis/regional/v1/ai/auth/approvals/apr_1", "approval")]
    public async Task A_timeout_on_discovery_or_the_approval_read_is_a_typed_error(string hang, string call)
    {
        var issuer = new AgentIssuer { OnGet = _ => AgentIssuer.Json(new { data = new { status = "approved", action = "x" } }) };
        var auth = AuthOver(issuer, r => Is(r, hang) ? new HangResponse() : null, c => c.Timeout = TimeSpan.FromMilliseconds(150));
        var e = await Assert.ThrowsAsync<AuthFIException>(() => call == "mint" ? auth.GetTokenAsync() : auth.GetApprovalAsync("apr_1"));
        Assert.Equal("timeout", e.Code);
    }

    private sealed class HangResponse : HttpResponseMessage
    {
        public HangResponse() { Content = new StreamContent(new HangStream()); }
    }

    private sealed class HangStream : Stream
    {
        public override int Read(byte[] b, int o, int c) { Thread.Sleep(Timeout.Infinite); return 0; }
        public override async Task<int> ReadAsync(byte[] b, int o, int c, CancellationToken ct) { await Task.Delay(Timeout.Infinite, ct); return 0; }
        public override async ValueTask<int> ReadAsync(Memory<byte> m, CancellationToken ct = default) { await Task.Delay(Timeout.Infinite, ct); return 0; }
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException(); public override long Position { get => 0; set { } }
        public override void Flush() { } public override long Seek(long o, SeekOrigin s) => 0; public override void SetLength(long v) { }
        public override void Write(byte[] b, int o, int c) { }
    }

    [Fact]
    public async Task A_connection_failure_on_the_approval_read_is_a_typed_error_without_the_cause()
    {
        var issuer = new AgentIssuer { OnGet = _ => throw new HttpRequestException("secret-host-detail") };
        var e = await Assert.ThrowsAsync<AuthFIException>(() => issuer.Auth().GetApprovalAsync("apr_1"));
        Assert.Equal("connection_failed", e.Code);
        Assert.DoesNotContain("secret-host-detail", e.Message);
    }

    // ---- token cache bound ----

    private static int CacheCount(AgentAuth a) =>
        ((System.Collections.IDictionary)typeof(AgentAuth).GetField("_cache", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(a)!).Count;

    [Fact]
    public async Task Eviction_drops_the_oldest_entry_and_keeps_the_rest()
    {
        var issuer = new AgentIssuer();
        var auth = issuer.Auth();
        for (var i = 0; i < 64; i++) { await auth.GetTokenAsync("api_" + i); issuer.Clock.Now += TimeSpan.FromSeconds(1); }
        Assert.Equal(64, issuer.Mints);
        await auth.GetTokenAsync("api_64"); // evicts api_0
        Assert.Equal(65, issuer.Mints);
        await auth.GetTokenAsync("api_63"); await auth.GetTokenAsync("api_1"); await auth.GetTokenAsync("api_64");
        Assert.Equal(65, issuer.Mints); // the others are still cached
        await auth.GetTokenAsync("api_0");
        Assert.Equal(66, issuer.Mints); // the oldest was the one evicted
    }

    [Fact]
    public async Task Eviction_first_drops_every_expired_entry()
    {
        var issuer = new AgentIssuer { ExpiresIn = 120 };
        var auth = issuer.Auth();
        for (var i = 0; i < 64; i++) await auth.GetTokenAsync("api_" + i);
        issuer.Clock.Now += TimeSpan.FromMinutes(10);
        await auth.GetTokenAsync("fresh");
        Assert.Equal(1, CacheCount(auth));
    }

    [Fact]
    public async Task Replacing_a_stale_entry_of_a_full_cache_evicts_nothing_else()
    {
        var issuer = new AgentIssuer { ExpiresIn = 120 };
        var auth = issuer.Auth();
        for (var i = 0; i < 64; i++) { await auth.GetTokenAsync("api_" + i); issuer.Clock.Now += TimeSpan.FromSeconds(1); }
        await auth.GetTokenAsync("api_0"); // stale, present: replaced in place
        Assert.Equal(64, CacheCount(auth));
        Assert.Equal(65, issuer.Mints);
        await auth.GetTokenAsync("api_63");
        Assert.Equal(65, issuer.Mints);
    }

    // ---- ForgetTokenAsync ----

    [Fact]
    public async Task Forgetting_one_resource_leaves_the_others_cached()
    {
        var issuer = new AgentIssuer();
        var auth = issuer.Auth();
        await auth.GetTokenAsync("r1"); await auth.GetTokenAsync("r2"); await auth.GetTokenAsync();
        await auth.ForgetTokenAsync("r1");
        await auth.GetTokenAsync("r2"); await auth.GetTokenAsync();
        Assert.Equal(3, issuer.Mints);
        await auth.GetTokenAsync("r1");
        Assert.Equal(4, issuer.Mints);
        await auth.ForgetTokenAsync();
        await auth.GetTokenAsync();
        Assert.Equal(5, issuer.Mints);
    }

    [Fact]
    public async Task A_401_drops_the_token_of_the_handlers_own_resource()
    {
        var issuer = new AgentIssuer();
        var status = HttpStatusCode.Unauthorized;
        var client = new HttpClient(new AuthFIBearerHandler(issuer.Auth(), "api://gw", new StubHandler(_ => new HttpResponseMessage(status))));
        await Assert.ThrowsAsync<AuthFIAgentRevokedException>(() => client.GetAsync("https://gateway.example/mcp"));
        status = HttpStatusCode.OK;
        await client.GetAsync("https://gateway.example/mcp");
        Assert.Equal(2, issuer.Mints);
        await client.GetAsync("https://gateway.example/mcp");
        Assert.Equal(2, issuer.Mints);
    }

    // ---- discovery ----

    [Fact]
    public async Task The_approval_endpoint_is_fetched_once()
    {
        var issuer = new AgentIssuer { OnGet = _ => AgentIssuer.Json(new { data = new { status = "approved", action = "x" } }) };
        var auth = issuer.Auth();
        await auth.GetApprovalAsync("apr_1"); await auth.GetApprovalAsync("apr_2");
        Assert.Equal(1, issuer.Handler.Requests.Count(p => p == "/.well-known/agent-configuration"));
    }

    [Fact]
    public async Task A_clock_that_goes_back_does_not_keep_discovery_forever()
    {
        var issuer = new AgentIssuer();
        var auth = issuer.Auth();
        await auth.GetTokenAsync("a");
        issuer.Clock.Now -= TimeSpan.FromHours(3);
        await auth.GetTokenAsync("b");
        Assert.Equal(2, issuer.Handler.Requests.Count(p => p == "/.well-known/oauth-authorization-server"));
    }

    [Fact]
    public async Task An_agent_configuration_without_an_issuer_is_judged_by_its_endpoints_alone()
    {
        var issuer = new AgentIssuer { OnGet = _ => AgentIssuer.Json(new { data = new { status = "approved", action = "x" } }) };
        var auth = AuthOver(issuer, r => Is(r, "/.well-known/agent-configuration") ? AgentIssuer.Json(new { endpoints = new { approval = AgentIssuer.Issuer + "/a/{id}" } }) : null);
        Assert.Equal("approved", (await auth.GetApprovalAsync("apr_1")).Status);
    }

    // ---- error text ----

    [Fact]
    public async Task Whitespace_in_a_server_description_is_one_space_and_trimmed()
    {
        var issuer = new AgentIssuer { OnMint = _ => AgentIssuer.OAuthError("invalid_request", "  boom \t\r\n  and  more  ") };
        var e = await Assert.ThrowsAsync<AuthFIException>(() => issuer.Auth().GetTokenAsync());
        Assert.EndsWith("(400, invalid_request): boom and more", e.Message);
    }

    // ---- delegated token ----

    [Fact]
    public async Task A_delegated_token_without_exp_expires_by_expires_in()
    {
        var issuer = new AgentIssuer { OnExchange = _ => AgentIssuer.Json(new { access_token = AgentIssuer.Jwt(new { sub = "user:ann", act = new { sub = AgentIssuer.AgentId } }), expires_in = 600 }) };
        var t = await issuer.Auth().ExchangeAsync(new Secret("t"));
        Assert.Equal(issuer.Clock.Now.AddSeconds(600), t.ExpiresAt);
        Assert.Equal(AgentIssuer.AgentId, t.Agent);
    }

    // ---- key file ----

    [Theory]
    [InlineData(0x1A0, false)]  // 0640: the owner's group may read (a Kubernetes fsGroup mount)
    [InlineData(0x190, true)]   // 0620
    [InlineData(0x188, true)]   // 0610
    [InlineData(0x184, true)]   // 0604
    [InlineData(0x182, true)]   // 0602
    [InlineData(0x181, true)]   // 0601
    [InlineData(0x180, false)]  // 0600
    [InlineData(0x100, false)]  // 0400
    public void Any_group_or_other_bit_on_a_key_file_refuses_it(int mode, bool refused)
    {
        if (OperatingSystem.IsWindows()) return;
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, AgentKey.Generate("EdDSA").ExportPrivatePem().Reveal());
            File.SetUnixFileMode(path, (UnixFileMode)mode);
            Environment.SetEnvironmentVariable("AUTHFI_ISSUER", AgentIssuer.Issuer);
            Environment.SetEnvironmentVariable("AUTHFI_AGENT_ID", AgentIssuer.AgentId);
            Environment.SetEnvironmentVariable("AUTHFI_AGENT_KEY", null);
            Environment.SetEnvironmentVariable("AUTHFI_AGENT_KEY_FILE", path);
            if (refused) Assert.Throws<AuthFIConfigurationException>(AgentAuth.FromEnvironment);
            else Assert.NotNull(AgentAuth.FromEnvironment());
        }
        finally
        {
            foreach (var n in new[] { "AUTHFI_ISSUER", "AUTHFI_AGENT_ID", "AUTHFI_AGENT_KEY_FILE" }) Environment.SetEnvironmentVariable(n, null);
            File.Delete(path);
        }
    }

    // ---- gateway ----

    private static string Meta(string inner) => "{\"isError\":true,\"content\":[],\"_meta\":{\"io.authfi/refusal\":" + inner + "}}";
    private static GatewayAnswer ReadMeta(string inner) => GatewayAnswer.Read(JsonDocument.Parse(Meta(inner)).RootElement);

    [Theory]
    [InlineData("..", false)]
    [InlineData(".", false)]
    [InlineData(".x", false)]
    [InlineData("-x", false)]
    [InlineData("_x", false)]
    [InlineData("a.b", false)]
    [InlineData("a/b", false)]
    [InlineData("apr_1:x-y", true)]
    [InlineData("0", true)]
    public void A_hold_id_has_the_shape_of_an_id(string id, bool hold)
    {
        var a = GatewayAnswer.Read(true, $"Waiting for approval {id} (approval_required). A person must approve this action");
        Assert.Equal(hold ? GatewayAnswerKind.ApprovalRequired : GatewayAnswerKind.Allowed, a.Kind);
        var m = ReadMeta("{\"code\":\"c\",\"approval_id\":\"" + id + "\"}");
        Assert.Equal(hold ? id : null, m.ApprovalId);
    }

    [Fact]
    public void An_id_may_be_128_characters_and_not_129_and_not_end_in_a_newline()
    {
        var ok = "a" + new string('b', 127);
        Assert.Equal(GatewayAnswerKind.ApprovalRequired, GatewayAnswer.Read(true, $"Waiting for approval {ok} (approval_pending). A person must approve this action").Kind);
        Assert.Equal(GatewayAnswerKind.Allowed, GatewayAnswer.Read(true, $"Waiting for approval {ok}b (approval_pending). A person must approve this action").Kind);
        Assert.Equal(ok, ReadMeta("{\"code\":\"c\",\"approval_id\":\"" + ok + "\"}").ApprovalId);
        Assert.Null(ReadMeta("{\"code\":\"c\",\"approval_id\":\"" + ok + "b\"}").ApprovalId);
        Assert.Null(ReadMeta("{\"code\":\"c\",\"approval_id\":\"abc\\n\"}").ApprovalId);
        Assert.Null(ReadMeta("{\"code\":\"c\",\"approval_id\":\"\\u0663\\u0664\"}").ApprovalId);
    }

    [Fact]
    public void A_hold_code_longer_than_64_is_no_hold()
    {
        var code = "approval_required" + new string('x', 48); // 65 chars
        Assert.Equal(65, code.Length);
        Assert.Equal(GatewayAnswerKind.Allowed, GatewayAnswer.Read(true, $"Waiting for approval abc ({code}). A person must approve this action").Kind);
    }

    [Fact]
    public void A_refusals_free_text_is_one_short_plain_line()
    {
        var text = ReadMeta("{\"code\":\"x\",\"reason\":\"a\\u0007b\\u200bc\\u2028d\\n\\ne\"}").ModelText();
        Assert.Equal("Refused by AuthFI (x).", text); // a model never reads the free text
        var longReason = ReadMeta("{\"code\":\"x\",\"reason\":\"" + new string('r', 1000) + "\"}").ModelText();
        Assert.Equal("Refused by AuthFI (x).", longReason);
    }

    [Fact]
    public void A_refusal_code_and_scope_are_shown_only_in_their_own_alphabet()
    {
        Assert.Equal("Refused by AuthFI (refused).", ReadMeta("{\"code\":\"Has Space\"}").ModelText());
        Assert.Equal("Refused by AuthFI (" + new string((char)97, 64) + ").", ReadMeta("{\"code\":\"" + new string((char)97, 65) + "\"}").ModelText());
        Assert.Equal("Refused by AuthFI (" + new string('a', 64) + ").", ReadMeta("{\"code\":\"" + new string('a', 64) + "\"}").ModelText());
        Assert.Equal("Refused by AuthFI (e1).", ReadMeta("{\"error\":\"e1\"}").ModelText());
        Assert.Equal("Refused by AuthFI (c). The call needs the scope tools:*@x/y.", ReadMeta("{\"code\":\"c\",\"required_scope\":\"tools:*@x/y\"}").ModelText());
        Assert.Equal("Refused by AuthFI (c).", ReadMeta("{\"code\":\"c\",\"required_scope\":\"a b\"}").ModelText());
        Assert.Equal("Refused by AuthFI (c). The call needs the scope " + new string((char)115, 100) + ".", ReadMeta("{\"code\":\"c\",\"required_scope\":\"" + new string((char)115, 101) + "\"}").ModelText());
        Assert.Equal("Refused by AuthFI (c). The call needs the scope " + new string('s', 100) + ".", ReadMeta("{\"code\":\"c\",\"required_scope\":\"" + new string('s', 100) + "\"}").ModelText());
        Assert.Equal("Refused by AuthFI (c).", ReadMeta("{\"code\":\"c\",\"required_scope\":\"   \"}").ModelText());
        Assert.Equal("Refused by AuthFI (c).", ReadMeta("{\"code\":\"c\",\"reason\":\"  \"}").ModelText());
    }
}
