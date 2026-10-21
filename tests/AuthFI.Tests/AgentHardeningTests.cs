using System.Net;
using System.Security.Cryptography;
using System.Text;
using AuthFI.Agents;
using Xunit;

namespace AuthFI.Tests;

/// <summary>The checks the agent side makes on what the issuer tells it, and on what it hands back.</summary>
public class AgentHardeningTests
{
    private static HttpResponseMessage Delegated(string sub, string actSub, long? exp = null) =>
        AgentIssuer.Json(new { access_token = AgentIssuer.Jwt(exp is null ? (object)new { sub, act = new { sub = actSub } } : new { sub, act = new { sub = actSub }, exp }), expires_in = 600 });

    private static AgentAuth AuthOver(AgentIssuer issuer, Func<HttpRequestMessage, HttpResponseMessage?> over) =>
        issuer.Auth(o => o.HttpClient = new HttpClient(new StubHandler(r => over(r) ?? issuer.Handler.Respond(r))));

    [Fact]
    public async Task A_delegated_token_for_another_agent_is_refused()
    {
        var issuer = new AgentIssuer { OnExchange = _ => Delegated("user:ann", "agent:agt_someone_else") };
        var e = await Assert.ThrowsAsync<AuthFIException>(() => issuer.Auth().ExchangeAsync(new Secret("t")));
        Assert.Equal("invalid_response", e.Code);
    }

    [Fact]
    public async Task A_delegated_token_expires_when_its_exp_says()
    {
        var issuer = new AgentIssuer();
        var exp = issuer.Clock.Now.AddSeconds(90).ToUnixTimeSeconds();
        issuer.OnExchange = _ => Delegated("user:ann", "agent:" + AgentIssuer.AgentId, exp);
        var t = await issuer.Auth().ExchangeAsync(new Secret("t"));
        Assert.Equal(exp, t.ExpiresAt.ToUnixTimeSeconds());
    }

    [Fact]
    public async Task An_approval_url_off_the_issuers_host_or_over_http_is_dropped()
    {
        foreach (var url in new[] { "https://evil.example/approve#t=x", "http://acme.authfi.io/approve#t=x", "https://u:p@acme.authfi.io/a" })
        {
            var issuer = new AgentIssuer { OnCiba = _ => AgentIssuer.Json(new { auth_req_id = "r", expires_in = 300, interval = 5, approval_url = url }) };
            Assert.Null((await issuer.Auth().BackchannelAuthorizeAsync("a@b.c", "m")).ApprovalUrl);
        }
        var ours = new AgentIssuer { OnCiba = _ => AgentIssuer.Json(new { auth_req_id = "r", expires_in = 300, approval_url = "https://acme.authfi.io/approve#t=x" }) };
        Assert.Equal("https://acme.authfi.io/approve#t=x", (await ours.Auth().BackchannelAuthorizeAsync("a@b.c", "m")).ApprovalUrl);
    }

    [Fact]
    public async Task The_ciba_endpoint_must_be_on_the_issuers_host()
    {
        var issuer = new AgentIssuer();
        var auth = AuthOver(issuer, r => r.RequestUri!.AbsolutePath == "/.well-known/oauth-authorization-server"
            ? AgentIssuer.Json(new { issuer = AgentIssuer.Issuer, token_endpoint = AgentIssuer.TokenUrl, backchannel_authentication_endpoint = "https://evil.example/ciba" })
            : null);
        var e = await Assert.ThrowsAsync<AuthFIException>(() => auth.BackchannelAuthorizeAsync("a@b.c", "m"));
        Assert.Equal("ciba_unavailable", e.Code);
        Assert.Empty(issuer.Posts);
    }

    [Fact]
    public async Task An_agent_configuration_that_names_another_issuer_is_refused()
    {
        var issuer = new AgentIssuer();
        var auth = AuthOver(issuer, r => r.RequestUri!.AbsolutePath == "/.well-known/agent-configuration"
            ? AgentIssuer.Json(new { issuer = "https://evil.example", endpoints = new { approval = AgentIssuer.Issuer + "/a/{id}" } }) : null);
        Assert.Equal("metadata_invalid", (await Assert.ThrowsAsync<AuthFIException>(() => auth.GetApprovalAsync("apr_1"))).Code);
    }

    [Fact]
    public async Task A_failed_agent_configuration_is_not_remembered_as_no_approvals()
    {
        var issuer = new AgentIssuer { OnGet = _ => AgentIssuer.Json(new { data = new { status = "approved", action = "refund" } }) };
        var fail = true;
        var auth = AuthOver(issuer, r => fail && r.RequestUri!.AbsolutePath == "/.well-known/agent-configuration" ? new HttpResponseMessage(HttpStatusCode.InternalServerError) : null);
        await Assert.ThrowsAsync<AuthFIException>(() => auth.GetApprovalAsync("apr_1"));
        fail = false;
        Assert.Equal("approved", (await auth.GetApprovalAsync("apr_1")).Status);
    }

    [Theory]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("")]
    public async Task An_approval_id_that_is_a_path_segment_is_refused(string id)
    {
        await Assert.ThrowsAsync<AuthFIConfigurationException>(() => new AgentIssuer().Auth().GetApprovalAsync(id));
    }

    [Fact]
    public async Task The_token_cache_is_bounded()
    {
        var issuer = new AgentIssuer();
        var auth = issuer.Auth();
        for (var i = 0; i < 200; i++) await auth.GetTokenAsync("api_" + i);
        var cached = (System.Collections.IDictionary)typeof(AgentAuth).GetField("_cache", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(auth)!;
        Assert.True(cached.Count <= 64, cached.Count.ToString());
        Assert.Equal(200, issuer.Mints);
    }

    [Fact]
    public async Task An_answer_over_a_megabyte_is_a_transport_failure_not_a_buffer()
    {
        var issuer = new AgentIssuer { OnMint = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(new string('a', (1 << 20) + 10)) } };
        var e = await Assert.ThrowsAsync<AuthFIException>(() => issuer.Auth().GetTokenAsync());
        Assert.Equal("connection_failed", e.Code);
    }

    private sealed class HangHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            await Task.Delay(Timeout.Infinite, ct);
            return null!;
        }
    }

    [Fact]
    public async Task A_timeout_is_a_typed_error_and_a_callers_cancellation_is_not()
    {
        var o = new AgentAuthOptions
        {
            Issuer = AgentIssuer.Issuer, AgentId = AgentIssuer.AgentId, Key = AgentKey.Generate("EdDSA"),
            HttpClient = new HttpClient(new HangHandler()) { Timeout = TimeSpan.FromMilliseconds(100) },
        };
        var e = await Assert.ThrowsAsync<AuthFIException>(() => new AgentAuth(o).GetTokenAsync());
        Assert.Equal("timeout", e.Code);
        using var cts = new CancellationTokenSource(50);
        o.HttpClient = new HttpClient(new HangHandler());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new AgentAuth(o).GetTokenAsync(null, cts.Token));
    }

    [Fact]
    public void An_issuer_with_credentials_is_refused_and_never_printed()
    {
        foreach (var issuer in new[] { "https://user:pw@acme.authfi.io", "https://@acme.authfi.io" })
            Assert.Throws<AuthFIConfigurationException>(() => new AgentAuth(new AgentAuthOptions { Issuer = issuer, AgentId = "a", Key = AgentKey.Generate("EdDSA") }));
    }

    [Fact]
    public async Task A_401_from_the_gateway_drops_the_cached_token_so_the_next_request_mints_afresh()
    {
        var issuer = new AgentIssuer();
        var status = HttpStatusCode.Unauthorized;
        var inner = new StubHandler(_ => new HttpResponseMessage(status));
        var client = new HttpClient(new AuthFIBearerHandler(issuer.Auth(), null, inner));
        await Assert.ThrowsAsync<AuthFIAgentRevokedException>(() => client.GetAsync("https://gateway.example/mcp"));
        status = HttpStatusCode.OK;
        await client.GetAsync("https://gateway.example/mcp");
        Assert.Equal(2, issuer.Mints);
    }

    [Fact]
    public void The_default_gateway_handler_does_not_follow_redirects()
    {
        var handler = new AuthFIBearerHandler(new AgentIssuer().Auth());
        var inner = (SocketsHttpHandler)typeof(DelegatingHandler).GetProperty("InnerHandler")!.GetValue(handler)!;
        Assert.False(inner.AllowAutoRedirect);
    }

    [Fact]
    public void A_pkcs8_ps256_key_is_3072_bits()
    {
        var pem = AgentKey.Generate("PS256").ExportPrivatePem().Reveal();
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        Assert.Equal(3072, rsa.KeySize);
    }

    [Fact]
    public void A_key_file_others_can_read_is_refused()
    {
        if (OperatingSystem.IsWindows()) return;
        var key = AgentKey.Generate("EdDSA", "k1");
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, key.ExportPrivatePem().Reveal());
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);
            Environment.SetEnvironmentVariable("AUTHFI_ISSUER", AgentIssuer.Issuer);
            Environment.SetEnvironmentVariable("AUTHFI_AGENT_ID", AgentIssuer.AgentId);
            Environment.SetEnvironmentVariable("AUTHFI_AGENT_KEY", null);
            Environment.SetEnvironmentVariable("AUTHFI_AGENT_KEY_FILE", path);
            Assert.Throws<AuthFIConfigurationException>(AgentAuth.FromEnvironment);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            Assert.Equal(AgentIssuer.AgentId, AgentAuth.FromEnvironment().AgentId);
        }
        finally
        {
            foreach (var n in new[] { "AUTHFI_ISSUER", "AUTHFI_AGENT_ID", "AUTHFI_AGENT_KEY_FILE" }) Environment.SetEnvironmentVariable(n, null);
            File.Delete(path);
        }
    }
}
