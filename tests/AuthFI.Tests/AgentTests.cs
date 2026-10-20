using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AuthFI.Agents;
using Xunit;

namespace AuthFI.Tests;

/// <summary>An issuer that checks the agent's client assertions against its registered key and answers from scripts.</summary>
internal sealed class AgentIssuer
{
    public const string Issuer = "https://acme.authfi.io";
    public const string TokenUrl = Issuer + "/oauth/token";
    public const string CibaUrl = Issuer + "/apis/regional/v1/ai/auth/backchannel-authorize";
    public const string AgentId = "agt_1a011907ab0445ec9e58af117c6f3177";

    public AgentKey Key { get; }
    public FakeClock Clock { get; } = new();
    public List<(string Url, Dictionary<string, string> Form, string? Bearer)> Posts { get; } = new();
    public int Mints;
    public Func<int, HttpResponseMessage>? OnMint;                       // by mint number
    public Func<Dictionary<string, string>, HttpResponseMessage>? OnCiba;
    public Func<Dictionary<string, string>, HttpResponseMessage>? OnCibaPoll;
    public Func<Dictionary<string, string>, HttpResponseMessage>? OnExchange;
    public Func<HttpRequestMessage, HttpResponseMessage>? OnGet;
    public int ExpiresIn = 900;
    public string AccessToken = "tok-initial";

    public AgentIssuer(AgentKey? key = null) => Key = key ?? AgentKey.Generate("EdDSA", "agent-key-1");

    public static HttpResponseMessage Json(object o, HttpStatusCode code = HttpStatusCode.OK) =>
        new(code) { Content = new StringContent(JsonSerializer.Serialize(o), Encoding.UTF8, "application/json") };

    public static HttpResponseMessage OAuthError(string error, string? description = null, HttpStatusCode code = HttpStatusCode.BadRequest) =>
        Json(new { error, error_description = description }, code);

    public static string Jwt(object claims)
    {
        var h = TestKey.B64u(Encoding.UTF8.GetBytes("""{"alg":"EdDSA","typ":"at+jwt","kid":"x"}"""));
        return h + "." + TestKey.B64u(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(claims))) + ".c2ln";
    }

    public StubHandler Handler => _handler ??= new StubHandler(Answer);
    private StubHandler? _handler;

    private HttpResponseMessage Answer(HttpRequestMessage r)
    {
        var url = r.RequestUri!.GetLeftPart(UriPartial.Path);
        if (r.Method == HttpMethod.Get)
        {
            if (url == Issuer + "/.well-known/oauth-authorization-server")
                return Json(new { issuer = Issuer, token_endpoint = TokenUrl, backchannel_authentication_endpoint = CibaUrl });
            if (url == Issuer + "/.well-known/agent-configuration")
                return Json(new { issuer = Issuer, endpoints = new { approval = Issuer + "/apis/regional/v1/ai/auth/approvals/{id}" } });
            return OnGet?.Invoke(r) ?? new HttpResponseMessage(HttpStatusCode.NotFound);
        }
        var form = r.Content!.ReadAsStringAsync().GetAwaiter().GetResult()
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => Uri.UnescapeDataString(p[0].Replace('+', ' ')), p => Uri.UnescapeDataString(p[1].Replace('+', ' ')));
        Posts.Add((url, form, r.Headers.Authorization?.Parameter));
        if (form.TryGetValue("client_assertion", out var assertion)) CheckAssertion(assertion);
        if (url == CibaUrl) return OnCiba?.Invoke(form) ?? Json(new { auth_req_id = "req-1", expires_in = 300, interval = 5 });
        var grant = form["grant_type"];
        if (grant == "client_credentials")
        {
            var n = ++Mints;
            return OnMint?.Invoke(n) ?? Json(new { access_token = AccessToken + "-" + n, token_type = "Bearer", expires_in = ExpiresIn });
        }
        if (grant == "urn:openid:params:grant-type:ciba") return OnCibaPoll!(form);
        if (grant == "urn:ietf:params:oauth:grant-type:token-exchange") return OnExchange!(form);
        return OAuthError("unsupported_grant_type");
    }

    // The same checks the platform makes: signature by the registered key, iss = sub = the agent, aud = token endpoint, short life, unique jti.
    private readonly HashSet<string> _jtis = new();
    private void CheckAssertion(string jwt)
    {
        var parts = jwt.Split('.');
        var header = JsonDocument.Parse(B64.Decode(parts[0])).RootElement;
        var claims = JsonDocument.Parse(B64.Decode(parts[1])).RootElement;
        var jwk = JsonDocument.Parse(Key.PublicJwk().ToJsonString()).RootElement;
        var vk = VerificationKey.FromJwk(jwk)!;
        Assert.Equal(Key.Alg, header.GetProperty("alg").GetString());
        Assert.Equal(Key.Kid, header.GetProperty("kid").GetString());
        Assert.True(vk.Verify(Key.Alg, Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), B64.Decode(parts[2])), "assertion signature");
        Assert.Equal(AgentId, claims.GetProperty("iss").GetString());
        Assert.Equal(AgentId, claims.GetProperty("sub").GetString());
        Assert.Equal(TokenUrl, claims.GetProperty("aud").GetString());
        var life = claims.GetProperty("exp").GetInt64() - claims.GetProperty("iat").GetInt64();
        Assert.InRange(life, 1, 120);
        Assert.True(_jtis.Add(claims.GetProperty("jti").GetString()!), "jti reused");
    }

    public AgentAuth Auth(Action<AgentAuthOptions>? edit = null)
    {
        var o = new AgentAuthOptions
        {
            Issuer = Issuer, AgentId = AgentId, Key = Key, HttpClient = new HttpClient(Handler), TimeProvider = Clock,
            Delay = (d, _) => { Clock.Now += d; return Task.CompletedTask; },
        };
        edit?.Invoke(o);
        return new AgentAuth(o);
    }

    public IEnumerable<Dictionary<string, string>> FormsTo(string url) => Posts.Where(p => p.Url == url).Select(p => p.Form);
}

public class AgentKeyTests
{
    public static IEnumerable<object[]> Algs => new[] { "EdDSA", "ES256", "PS256" }.Select(a => new object[] { a });

    [Theory, MemberData(nameof(Algs))]
    public void A_generated_key_signs_what_its_public_jwk_verifies(string alg)
    {
        var key = AgentKey.Generate(alg);
        var jwk = key.PublicJwk();
        Assert.Null(jwk["d"]);
        Assert.Null(jwk["p"]);
        Assert.Equal(alg, jwk["alg"]!.GetValue<string>());
        Assert.Equal(key.Kid, jwk["kid"]!.GetValue<string>());
        var vk = VerificationKey.FromJwk(JsonDocument.Parse(jwk.ToJsonString()).RootElement)!;
        var sig = key.Sign(Encoding.ASCII.GetBytes("data"));
        Assert.True(vk.Verify(alg, Encoding.ASCII.GetBytes("data"), sig));
        Assert.False(vk.Verify(alg, Encoding.ASCII.GetBytes("other"), sig));
    }

    [Theory, MemberData(nameof(Algs))]
    public void A_key_survives_its_own_pem(string alg)
    {
        var key = AgentKey.Generate(alg, "k-1");
        var loaded = AgentKey.Load(key.ExportPrivatePem().Reveal());
        Assert.Equal(alg, loaded.Alg);
        Assert.Equal(key.PublicJwk().ToJsonString(), AgentKey.Load(key.ExportPrivatePem().Reveal(), "k-1").PublicJwk().ToJsonString());
        var vk = VerificationKey.FromJwk(JsonDocument.Parse(key.PublicJwk().ToJsonString()).RootElement)!;
        Assert.True(vk.Verify(alg, new byte[] { 1, 2, 3 }, loaded.Sign(new byte[] { 1, 2, 3 })));
    }

    [Fact]
    public void Without_a_kid_the_thumbprint_names_the_key_and_is_stable()
    {
        var key = AgentKey.Generate("EdDSA");
        Assert.Equal(AgentKey.Load(key.ExportPrivatePem().Reveal()).Kid, key.Kid);
        Assert.NotEqual(AgentKey.Generate("EdDSA").Kid, key.Kid);
    }

    [Fact]
    public void Loads_the_legacy_rsa_and_ec_pem_labels()
    {
        var rsa = System.Security.Cryptography.RSA.Create(2048);
        Assert.Equal("PS256", AgentKey.Load(new string(System.Security.Cryptography.PemEncoding.Write("RSA PRIVATE KEY", rsa.ExportRSAPrivateKey()))).Alg);
        var ec = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        Assert.Equal("ES256", AgentKey.Load(new string(System.Security.Cryptography.PemEncoding.Write("EC PRIVATE KEY", ec.ExportECPrivateKey()))).Alg);
    }

    [Fact]
    public void Refuses_keys_it_cannot_use_with_a_message_that_echoes_nothing()
    {
        var weak = System.Security.Cryptography.RSA.Create(1024);
        var p384 = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP384);
        foreach (var pem in new[]
        {
            new string(System.Security.Cryptography.PemEncoding.Write("PRIVATE KEY", weak.ExportPkcs8PrivateKey())),
            new string(System.Security.Cryptography.PemEncoding.Write("PRIVATE KEY", p384.ExportPkcs8PrivateKey())),
            "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5LXNlY3JldA==\n-----END PRIVATE KEY-----",
            "garbage-secret-marker",
            "",
        })
        {
            var e = Assert.Throws<AuthFIConfigurationException>(() => AgentKey.Load(pem));
            Assert.DoesNotContain("secret", e.Message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("marker", e.Message);
        }
        Assert.Throws<AuthFIConfigurationException>(() => AgentKey.Generate("RS256"));
    }

    [Fact]
    public void The_key_prints_no_private_material()
    {
        var key = AgentKey.Generate("EdDSA", "k-1");
        var pem = key.ExportPrivatePem().Reveal();
        var body = pem.Split('\n')[1];
        Assert.DoesNotContain(body, key.ToString());
        Assert.DoesNotContain(body, key.ExportPrivatePem().ToString());
        Assert.DoesNotContain(body, System.Text.Json.JsonSerializer.Serialize(key.ExportPrivatePem()));
        Assert.Equal("AgentKey(kid=k-1, alg=EdDSA)", key.ToString());
    }
}

public class AgentAuthTests
{
    public static IEnumerable<object[]> Algs => new[] { "EdDSA", "ES256", "PS256" }.Select(a => new object[] { a });

    [Theory, MemberData(nameof(Algs))]
    public async Task Mints_a_token_with_a_private_key_jwt_for_each_key_type(string alg)
    {
        var issuer = new AgentIssuer(AgentKey.Generate(alg, "k1"));
        var token = await issuer.Auth().GetTokenAsync();
        Assert.Equal("tok-initial-1", token.Reveal());
        var form = issuer.FormsTo(AgentIssuer.TokenUrl).Single();
        Assert.Equal("client_credentials", form["grant_type"]);
        Assert.Equal(AgentIssuer.AgentId, form["client_id"]);
        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form["client_assertion_type"]);
        Assert.DoesNotContain("resource", form.Keys);
    }

    [Fact]
    public async Task Caches_until_a_minute_before_expiry_then_mints_again()
    {
        var issuer = new AgentIssuer();
        var auth = issuer.Auth();
        var a = (await auth.GetTokenAsync()).Reveal();
        issuer.Clock.Now += TimeSpan.FromSeconds(839);
        Assert.Equal(a, (await auth.GetTokenAsync()).Reveal());
        Assert.Equal(1, issuer.Mints);
        issuer.Clock.Now += TimeSpan.FromSeconds(2);
        Assert.NotEqual(a, (await auth.GetTokenAsync()).Reveal());
        Assert.Equal(2, issuer.Mints);
    }

    [Fact]
    public async Task A_token_that_lives_a_minute_or_less_is_never_cached()
    {
        var issuer = new AgentIssuer { ExpiresIn = 60 };
        var auth = issuer.Auth();
        await auth.GetTokenAsync();
        await auth.GetTokenAsync();
        Assert.Equal(2, issuer.Mints);
    }

    [Fact]
    public async Task Each_resource_has_its_own_token_and_is_sent_as_resource()
    {
        var issuer = new AgentIssuer();
        var auth = issuer.Auth();
        var api = (await auth.GetTokenAsync("api_orders")).Reveal();
        var other = (await auth.GetTokenAsync("api_billing")).Reveal();
        Assert.Equal(api, (await auth.GetTokenAsync("api_orders")).Reveal());
        Assert.NotEqual(api, other);
        Assert.Equal(new[] { "api_orders", "api_billing" }, issuer.FormsTo(AgentIssuer.TokenUrl).Select(f => f["resource"]));
    }

    [Fact]
    public async Task Concurrent_callers_share_one_mint()
    {
        var issuer = new AgentIssuer();
        var auth = issuer.Auth();
        await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => auth.GetTokenAsync()));
        Assert.Equal(1, issuer.Mints);
    }

    [Fact]
    public async Task Retries_a_mint_once_after_a_reset_connection_and_not_twice()
    {
        var issuer = new AgentIssuer();
        issuer.OnMint = n => n == 1 ? throw new HttpRequestException("reset", new IOException("reset")) : AgentIssuer.Json(new { access_token = "ok", expires_in = 900 });
        Assert.Equal("ok", (await issuer.Auth().GetTokenAsync()).Reveal());

        var always = new AgentIssuer { OnMint = _ => throw new HttpRequestException("reset", new SocketException()) };
        var e = await Assert.ThrowsAsync<AuthFIException>(() => always.Auth().GetTokenAsync());
        Assert.Equal("connection_failed", e.Code);
        Assert.Equal(2, always.Mints);
    }

    [Fact]
    public async Task Does_not_retry_a_mint_the_server_answered()
    {
        var issuer = new AgentIssuer { OnMint = _ => AgentIssuer.OAuthError("invalid_client", "unknown agent", HttpStatusCode.Unauthorized) };
        await Assert.ThrowsAsync<AuthFIAgentRevokedException>(() => issuer.Auth().GetTokenAsync());
        Assert.Equal(1, issuer.Mints);
    }

    [Fact]
    public async Task A_refusal_is_typed_and_its_text_carries_no_token()
    {
        var jwt = AgentIssuer.Jwt(new { sub = "x" });
        var issuer = new AgentIssuer { OnMint = _ => AgentIssuer.OAuthError("invalid_target", "no. you sent " + jwt + " to this", HttpStatusCode.Forbidden) };
        var e = await Assert.ThrowsAsync<AuthFIRefusedException>(() => issuer.Auth().GetTokenAsync("https://not-granted.example.com"));
        Assert.Equal("invalid_target", e.Code);
        Assert.Equal(403, e.Status);
        Assert.DoesNotContain(jwt, e.ToString());
        Assert.DoesNotContain("eyJ", e.ToString());
    }

    [Fact]
    public async Task Refuses_discovery_that_names_another_issuer_and_needs_no_default_url()
    {
        var issuer = new AgentIssuer();
        issuer.Handler.GetHashCode();
        var o = new AgentAuthOptions { Issuer = "https://other.authfi.io", AgentId = "a", Key = issuer.Key, HttpClient = new HttpClient(issuer.Handler) };
        await Assert.ThrowsAnyAsync<AuthFIException>(() => new AgentAuth(o).GetTokenAsync());
        Assert.Throws<AuthFIConfigurationException>(() => new AgentAuth(new AgentAuthOptions { AgentId = "a", Key = issuer.Key }));
        Assert.Throws<AuthFIConfigurationException>(() => new AgentAuth(new AgentAuthOptions { Issuer = "http://acme.authfi.io", AgentId = "a", Key = issuer.Key }));
        Assert.Throws<AuthFIConfigurationException>(() => new AgentAuth(new AgentAuthOptions { Issuer = AgentIssuer.Issuer, Key = issuer.Key }));
        Assert.Throws<AuthFIConfigurationException>(() => new AgentAuth(new AgentAuthOptions { Issuer = AgentIssuer.Issuer, AgentId = "a" }));
    }

    [Fact]
    public async Task From_environment_builds_the_agent_from_a_pem()
    {
        var key = AgentKey.Generate("ES256", "env-k");
        Environment.SetEnvironmentVariable("AUTHFI_ISSUER", AgentIssuer.Issuer);
        Environment.SetEnvironmentVariable("AUTHFI_AGENT_ID", AgentIssuer.AgentId);
        Environment.SetEnvironmentVariable("AUTHFI_AGENT_KEY", key.ExportPrivatePem().Reveal());
        Environment.SetEnvironmentVariable("AUTHFI_AGENT_KEY_ID", "env-k");
        try
        {
            var auth = AgentAuth.FromEnvironment();
            Assert.Equal(AgentIssuer.AgentId, auth.AgentId);
            Assert.DoesNotContain(key.ExportPrivatePem().Reveal().Split('\n')[1], auth.ToString());
        }
        finally
        {
            foreach (var n in new[] { "AUTHFI_ISSUER", "AUTHFI_AGENT_ID", "AUTHFI_AGENT_KEY", "AUTHFI_AGENT_KEY_ID" })
                Environment.SetEnvironmentVariable(n, null);
        }
        Assert.Throws<AuthFIConfigurationException>(AgentAuth.FromEnvironment);
        await Task.CompletedTask;
    }

    // ---- acting for a person ----

    private static HttpResponseMessage Delegated(string sub, string actSub) =>
        AgentIssuer.Json(new { access_token = AgentIssuer.Jwt(new { sub, act = new { sub = actSub }, scope = "model:use mcp:call" }), expires_in = 600, token_type = "Bearer" });

    [Theory]
    [InlineData("user:ann@example.com", "agent:agt_1a011907ab0445ec9e58af117c6f3177", "ann@example.com", "agt_1a011907ab0445ec9e58af117c6f3177")]
    [InlineData("ann@example.com", "agt_1a011907ab0445ec9e58af117c6f3177", "ann@example.com", "agt_1a011907ab0445ec9e58af117c6f3177")]
    public async Task CIBA_start_and_poll_give_a_delegated_token_for_either_spelling(string sub, string act, string person, string agent)
    {
        var issuer = new AgentIssuer { OnCibaPoll = _ => Delegated(sub, act) };
        var auth = issuer.Auth();
        var request = await auth.BackchannelAuthorizeAsync("ann@example.com", "Refund order 4411", new[] { "model:use", " mcp:call " }, 120);
        var form = issuer.FormsTo(AgentIssuer.CibaUrl).Single();
        Assert.Equal("ann@example.com", form["login_hint"]);
        Assert.Equal("Refund order 4411", form["binding_message"]);
        Assert.Equal("model:use mcp:call", form["scope"]);
        Assert.Equal("120", form["requested_expiry"]);
        Assert.Equal(AgentIssuer.AgentId, form["client_id"]);

        issuer.Clock.Now += TimeSpan.FromSeconds(5);
        var token = await auth.PollAsync(request, resource: "api_orders");
        Assert.NotNull(token);
        Assert.Equal(person, token!.Person);
        Assert.Equal(agent, token.Agent);
        Assert.Equal(new[] { "model:use", "mcp:call" }, token.Scopes);
        var poll = issuer.FormsTo(AgentIssuer.TokenUrl).Single();
        Assert.Equal("req-1", poll["auth_req_id"]);
        Assert.Equal("api_orders", poll["resource"]);
        Assert.Contains("client_assertion", poll.Keys);
    }

    [Fact]
    public async Task CIBA_requires_who_to_ask_and_what_they_will_read()
    {
        var auth = new AgentIssuer().Auth();
        await Assert.ThrowsAsync<AuthFIConfigurationException>(() => auth.BackchannelAuthorizeAsync("", "m"));
        await Assert.ThrowsAsync<AuthFIConfigurationException>(() => auth.BackchannelAuthorizeAsync("a@b.c", " "));
        await Assert.ThrowsAsync<AuthFIConfigurationException>(() => auth.BackchannelAuthorizeAsync("a@b.c", "m", expiresIn: 0));
    }

    [Fact]
    public async Task The_first_poll_waits_the_interval_and_sends_nothing_before_it()
    {
        var issuer = new AgentIssuer { OnCibaPoll = _ => AgentIssuer.OAuthError("authorization_pending") };
        var auth = issuer.Auth();
        var request = await auth.BackchannelAuthorizeAsync("a@b.c", "m");
        Assert.Null(await auth.PollAsync(request));
        Assert.Empty(issuer.FormsTo(AgentIssuer.TokenUrl));
        issuer.Clock.Now += TimeSpan.FromSeconds(5);
        Assert.Null(await auth.PollAsync(request));
        Assert.Single(issuer.FormsTo(AgentIssuer.TokenUrl));
        Assert.Null(await auth.PollAsync(request));
        Assert.Single(issuer.FormsTo(AgentIssuer.TokenUrl));
    }

    [Fact]
    public async Task Slow_down_widens_the_interval_by_five_seconds()
    {
        var calls = 0;
        var issuer = new AgentIssuer { OnCibaPoll = _ => ++calls == 1 ? AgentIssuer.OAuthError("slow_down") : AgentIssuer.OAuthError("authorization_pending") };
        var auth = issuer.Auth();
        var request = await auth.BackchannelAuthorizeAsync("a@b.c", "m");
        issuer.Clock.Now += TimeSpan.FromSeconds(5);
        Assert.Null(await auth.PollAsync(request));
        Assert.Equal(TimeSpan.FromSeconds(10), request.Interval);
        issuer.Clock.Now += TimeSpan.FromSeconds(9);
        Assert.Null(await auth.PollAsync(request));
        Assert.Equal(1, calls);
        issuer.Clock.Now += TimeSpan.FromSeconds(1);
        Assert.Null(await auth.PollAsync(request));
        Assert.Equal(2, calls);
        Assert.Equal(TimeSpan.FromSeconds(10), request.Interval);
    }

    [Theory]
    [InlineData("access_denied")]
    [InlineData("expired_token")]
    public async Task A_decision_against_the_agent_throws_at_once(string error)
    {
        var issuer = new AgentIssuer { OnCibaPoll = _ => AgentIssuer.OAuthError(error) };
        var auth = issuer.Auth();
        var request = await auth.BackchannelAuthorizeAsync("a@b.c", "m");
        issuer.Clock.Now += TimeSpan.FromSeconds(5);
        Assert.Equal(error, (await Assert.ThrowsAsync<AuthFIException>(() => auth.PollAsync(request))).Code);
    }

    [Fact]
    public async Task A_request_past_its_expiry_throws_without_asking()
    {
        var issuer = new AgentIssuer();
        var auth = issuer.Auth();
        var request = await auth.BackchannelAuthorizeAsync("a@b.c", "m");
        issuer.Clock.Now += TimeSpan.FromSeconds(301);
        Assert.Equal("expired_token", (await Assert.ThrowsAsync<AuthFIException>(() => auth.PollAsync(request))).Code);
        Assert.Empty(issuer.FormsTo(AgentIssuer.TokenUrl));
    }

    [Fact]
    public async Task Await_polls_at_the_request_pace_until_the_person_decides()
    {
        var polls = 0;
        var issuer = new AgentIssuer { OnCibaPoll = _ => ++polls < 3 ? AgentIssuer.OAuthError("authorization_pending") : Delegated("user:ann", "agent:agt_1a011907ab0445ec9e58af117c6f3177") };
        var auth = issuer.Auth();
        var request = await auth.BackchannelAuthorizeAsync("a@b.c", "m");
        var start = issuer.Clock.Now;
        var token = await auth.AwaitUserTokenAsync(request);
        Assert.Equal("ann", token.Person);
        Assert.Equal(3, polls);
        Assert.Equal(TimeSpan.FromSeconds(15), issuer.Clock.Now - start);
    }

    [Fact]
    public async Task Await_gives_up_with_authorization_pending_when_time_runs_out()
    {
        var issuer = new AgentIssuer { OnCibaPoll = _ => AgentIssuer.OAuthError("authorization_pending") };
        var auth = issuer.Auth();
        var request = await auth.BackchannelAuthorizeAsync("a@b.c", "m");
        var e = await Assert.ThrowsAsync<AuthFIException>(() => auth.AwaitUserTokenAsync(request, TimeSpan.FromSeconds(12)));
        Assert.Equal("authorization_pending", e.Code);
        Assert.InRange(issuer.FormsTo(AgentIssuer.TokenUrl).Count(), 1, 3);
    }

    [Fact]
    public async Task Exchange_sends_the_agents_token_as_the_actor_and_no_client_credentials()
    {
        var issuer = new AgentIssuer { OnExchange = _ => Delegated("user:ann", "agent:agt_1a011907ab0445ec9e58af117c6f3177") };
        var auth = issuer.Auth();
        var token = await auth.ExchangeAsync(new Secret("person-token"), "api_orders", new[] { "model:use" });
        Assert.Equal("ann", token.Person);
        var form = issuer.FormsTo(AgentIssuer.TokenUrl).Single(f => f["grant_type"].Contains("token-exchange"));
        Assert.Equal("person-token", form["subject_token"]);
        Assert.Equal("tok-initial-1", form["actor_token"]);
        Assert.Equal("api_orders", form["resource"]);
        Assert.Equal("model:use", form["scope"]);
        Assert.DoesNotContain("client_id", form.Keys);
        Assert.DoesNotContain("client_assertion", form.Keys);
    }

    [Fact]
    public async Task Requests_that_create_state_are_never_sent_again_after_a_reset()
    {
        var issuer = new AgentIssuer
        {
            OnCiba = _ => throw new HttpRequestException("reset", new IOException()),
            OnExchange = _ => throw new HttpRequestException("reset", new IOException()),
            OnCibaPoll = _ => throw new HttpRequestException("reset", new IOException()),
        };
        var auth = issuer.Auth();
        await Assert.ThrowsAsync<AuthFIException>(() => auth.BackchannelAuthorizeAsync("a@b.c", "m"));
        Assert.Single(issuer.FormsTo(AgentIssuer.CibaUrl));
        await Assert.ThrowsAsync<AuthFIException>(() => auth.ExchangeAsync(new Secret("t")));
        Assert.Single(issuer.FormsTo(AgentIssuer.TokenUrl), f => f["grant_type"].Contains("token-exchange"));
    }

    [Fact]
    public async Task Reads_an_approval_with_the_agents_own_token()
    {
        var issuer = new AgentIssuer
        {
            OnGet = r => r.Headers.Authorization?.Parameter == "tok-initial-1" && r.RequestUri!.AbsolutePath.EndsWith("/approvals/apr_1")
                ? AgentIssuer.Json(new { data = new { approval_id = "apr_1", status = "approved", action = "refund" } })
                : new HttpResponseMessage(HttpStatusCode.Forbidden),
        };
        var rec = await issuer.Auth().GetApprovalAsync("apr_1");
        Assert.Equal("approved", rec.Status);
        Assert.Equal("refund", rec.Action);
    }

    // ---- secrets ----

    [Fact]
    public async Task No_text_form_of_any_agent_object_or_failure_carries_a_credential()
    {
        const string marker = "zzz-credential-marker";
        var issuer = new AgentIssuer { AccessToken = marker, OnCibaPoll = _ => Delegated("user:ann", "agent:agt_1a011907ab0445ec9e58af117c6f3177") };
        issuer.OnExchange = _ => Delegated("user:ann", "agent:agt_1a011907ab0445ec9e58af117c6f3177");
        var auth = issuer.Auth();
        var token = await auth.GetTokenAsync();
        var request = await auth.BackchannelAuthorizeAsync("a@b.c", "m");
        issuer.Clock.Now += TimeSpan.FromSeconds(5);
        var delegated = await auth.PollAsync(request);
        var pem = issuer.Key.ExportPrivatePem().Reveal().Split('\n')[1];

        var texts = new List<string>
        {
            token.ToString(), $"{token}", auth.ToString(), request.ToString(), issuer.Key.ToString(),
            JsonSerializer.Serialize(token), JsonSerializer.Serialize(issuer.Key.ExportPrivatePem()),
        };
        Assert.NotNull(delegated);
        texts.Add(delegated!.ToString());
        texts.Add(JsonSerializer.Serialize(delegated.Token));
        foreach (var t in texts)
        {
            Assert.DoesNotContain(marker, t);
            Assert.DoesNotContain(pem, t);
            Assert.DoesNotContain("eyJ", t);
            Assert.DoesNotContain("req-1", t);
        }

        var failing = new AgentIssuer { OnMint = _ => AgentIssuer.OAuthError("invalid_request", "bad assertion " + marker + " req-1", HttpStatusCode.BadRequest) };
        var e = await Assert.ThrowsAsync<AuthFIException>(() => failing.Auth().GetTokenAsync());
        foreach (var assertion in failing.Posts.Select(p => p.Form["client_assertion"]))
        {
            Assert.DoesNotContain(assertion, e.ToString());
            foreach (var part in assertion.Split('.')) Assert.DoesNotContain(part, e.ToString());
        }
        Assert.DoesNotContain(pem, e.ToString());
    }
}
