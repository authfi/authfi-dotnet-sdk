using System.Net.Http.Json;
using System.Text.Json;
using AuthFI.Agents;
using Xunit;
using Xunit.Abstractions;

namespace AuthFI.Tests;

/// <summary>
/// Skipped unless AUTHFI_LIVE_ISSUER is set. Env: AUTHFI_LIVE_ISSUER, AUTHFI_LIVE_TENANT, AUTHFI_LIVE_DIR (holds user_api.tok),
/// AUTHFI_LIVE_API_AUDIENCE (granted to both agents), AUTHFI_LIVE_LOGIN_HINT (the probe person's email),
/// agent A (autonomous, EdDSA): AUTHFI_LIVE_AGENT_ID, AUTHFI_LIVE_AGENT_KEY_FILE, AUTHFI_LIVE_AGENT_KID;
/// agent B (delegated, PS256): AUTHFI_LIVE_B_ID, AUTHFI_LIVE_B_KEY_FILE, AUTHFI_LIVE_B_KID.
/// Token values are never printed.
/// </summary>
public class LiveAgentTests
{
    private readonly ITestOutputHelper _out;
    public LiveAgentTests(ITestOutputHelper output) => _out = output;
    private static string Env(string n) => Environment.GetEnvironmentVariable(n) ?? throw new InvalidOperationException(n + " is not set");

    private static AgentAuth Agent(string idVar, string keyVar, string kidVar) => new(new AgentAuthOptions
    {
        Issuer = Env("AUTHFI_LIVE_ISSUER"),
        AgentId = Env(idVar),
        Key = AgentKey.Load(File.ReadAllText(Env(keyVar)), Env(kidVar)),
    });

    private static AgentAuth A() => Agent("AUTHFI_LIVE_AGENT_ID", "AUTHFI_LIVE_AGENT_KEY_FILE", "AUTHFI_LIVE_AGENT_KID");
    private static AgentAuth C() => Agent("AUTHFI_LIVE_C_ID", "AUTHFI_LIVE_C_KEY_FILE", "AUTHFI_LIVE_C_KID");
    private static AgentAuth B() => Agent("AUTHFI_LIVE_B_ID", "AUTHFI_LIVE_B_KEY_FILE", "AUTHFI_LIVE_B_KID");

    private static AuthFIVerifier Verifier()
    {
        var o = new AuthFIVerifierOptions { Issuer = Env("AUTHFI_LIVE_ISSUER"), ExpectedTenantId = Env("AUTHFI_LIVE_TENANT") };
        o.Audiences.Add(Env("AUTHFI_LIVE_API_AUDIENCE"));
        return new AuthFIVerifier(o);
    }

    [LiveFact]
    public async Task The_SDK_mints_an_agent_token_and_the_SDK_verifier_accepts_it()
    {
        var agent = A();
        var token = await agent.GetTokenAsync(Env("AUTHFI_LIVE_API_AUDIENCE"));
        Assert.Equal(token.Reveal(), (await agent.GetTokenAsync(Env("AUTHFI_LIVE_API_AUDIENCE"))).Reveal()); // cached
        var claims = await Verifier().VerifyAsync(token);
        _out.WriteLine($"MINTED by the SDK (EdDSA key) and VERIFIED by the SDK: sub={claims.Sub} aud={string.Join(",", claims.Audience)} tenant={claims.TenantId}");
        Assert.Equal(Env("AUTHFI_LIVE_AGENT_ID"), claims.Sub);
        Assert.DoesNotContain(token.Reveal(), agent.ToString());

        var b = await Verifier().VerifyAsync(await B().GetTokenAsync(Env("AUTHFI_LIVE_API_AUDIENCE")));
        _out.WriteLine($"MINTED by the SDK (PS256 key) and VERIFIED by the SDK: sub={b.Sub}");
        Assert.Equal(Env("AUTHFI_LIVE_B_ID"), b.Sub);
    }

    [LiveFact]
    public async Task An_ES256_agent_mints_and_the_SDK_verifier_accepts_it()
    {
        var claims = await Verifier().VerifyAsync(await C().GetTokenAsync(Env("AUTHFI_LIVE_API_AUDIENCE")));
        _out.WriteLine($"MINTED by the SDK (ES256 key) and VERIFIED by the SDK: sub={claims.Sub}");
        Assert.Equal(Env("AUTHFI_LIVE_C_ID"), claims.Sub);
    }

    [LiveFact]
    public async Task The_gateways_answer_to_a_tool_call_is_read_as_allowed_refused_or_held()
    {
        var agent = A();
        var gateway = Env("AUTHFI_LIVE_ISSUER") + "/mcp";
        using var http = new HttpClient(new AuthFIBearerHandler(agent, gateway));
        async Task<JsonElement?> Rpc(string method, object? parameters)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, gateway)
            {
                Content = JsonContent.Create(new { jsonrpc = "2.0", id = 1, method, @params = parameters ?? new { } }),
            };
            req.Headers.Accept.ParseAdd("application/json");
            req.Headers.Accept.ParseAdd("text/event-stream");
            using var res = await http.SendAsync(req);
            var text = await res.Content.ReadAsStringAsync();
            var json = text.TrimStart().StartsWith("{") ? text : string.Join("", text.Split((char)10).Where(l => l.StartsWith("data:")).Select(l => l[5..].Trim()));
            _out.WriteLine($"{method}: HTTP {(int)res.StatusCode}");
            if (json.Length == 0) return null;
            var doc = JsonDocument.Parse(json).RootElement.Clone();
            return doc.TryGetProperty("result", out var r) ? r : null;
        }

        var list = await Rpc("tools/list", null);
        var tools = list is { } l && l.TryGetProperty("tools", out var t) ? t.EnumerateArray().Select(x => x.GetProperty("name").GetString()!).ToList() : new List<string>();
        _out.WriteLine($"tools listed: {tools.Count}");
        foreach (var name in tools.Take(3))
        {
            var result = await Rpc("tools/call", new { name, arguments = new { } });
            if (result is null) continue;
            var answer = GatewayAnswer.Read(result.Value);
            _out.WriteLine($"GATEWAY ANSWER for a call to {name}: {answer.Kind} code={answer.Code} requiredScope={answer.RequiredScope}");
            if (answer.Kind != GatewayAnswerKind.Allowed)
            {
                Assert.DoesNotContain(answer.ApprovalId ?? "~", answer.ModelText());
                return;
            }
        }
        _out.WriteLine("no refused or held answer was available to read on this project");
    }

    [LiveFact]
    public async Task A_resource_the_agent_may_not_address_is_a_typed_refusal()
    {
        var e = await Assert.ThrowsAnyAsync<AuthFIException>(() => A().GetTokenAsync("https://not-granted.example.com/api"));
        _out.WriteLine($"REFUSED resource not granted: {e.GetType().Name} code={e.Code} status={e.Status}");
        Assert.Equal("invalid_target", e.Code);
    }

    [LiveFact]
    public async Task A_person_approves_in_their_browser_and_the_agent_gets_a_token_for_them()
    {
        var agent = B();
        var resource = Env("AUTHFI_LIVE_API_AUDIENCE");
        var request = await agent.BackchannelAuthorizeAsync(Env("AUTHFI_LIVE_LOGIN_HINT"), "SDK live probe: no action", expiresIn: 120);
        _out.WriteLine($"CIBA started: {request}");
        Assert.Null(await agent.PollAsync(request)); // before the first interval nothing is sent
        Assert.NotNull(request.ApprovalUrl);

        // The person's browser: the link's token is the fragment, which a browser never sends to a server.
        var fragment = request.ApprovalUrl!.Split('#', 2)[1];
        var token = fragment.StartsWith("t=") ? fragment[2..] : fragment;
        using var browser = new HttpClient();
        var decide = await browser.PostAsJsonAsync(Env("AUTHFI_LIVE_ISSUER") + "/apis/regional/v1/ai/auth/backchannel-approval/decide",
            new { token, decision = "approve" });
        _out.WriteLine($"the person answered: HTTP {(int)decide.StatusCode}");
        Assert.True(decide.IsSuccessStatusCode);

        var delegated = await agent.AwaitUserTokenAsync(request, TimeSpan.FromSeconds(60), resource);
        _out.WriteLine($"CIBA token: person={delegated.Person} agent={delegated.Agent} scopes={string.Join(" ", delegated.Scopes)}");
        Assert.Equal(Env("AUTHFI_LIVE_LOGIN_HINT"), delegated.Person);
        Assert.Equal(Env("AUTHFI_LIVE_B_ID"), delegated.Agent);

        var claims = await Verifier().VerifyAsync(delegated.Token);
        _out.WriteLine($"the delegated token VERIFIED by the SDK: sub={claims.Sub} actor={claims.Actor} aud={string.Join(",", claims.Audience)}");
        Assert.Contains(Env("AUTHFI_LIVE_LOGIN_HINT"), claims.Sub);
        Assert.Contains(Env("AUTHFI_LIVE_B_ID"), claims.Actor ?? "");

        // Exchange needs a console-side delegation (an administrator grants the agent the right to act for this person).
        // Without it the platform refuses, and the SDK reports a typed refusal; with it, the exchange returns a token for the person.
        var owner = new Secret(File.ReadAllText(Path.Combine(Env("AUTHFI_LIVE_DIR"), "owner_api.tok")).Trim());
        try
        {
            var exchanged = await agent.ExchangeAsync(owner, resource);
            var exchangedClaims = await Verifier().VerifyAsync(exchanged.Token);
            _out.WriteLine($"EXCHANGED and VERIFIED: person={exchanged.Person} agent={exchanged.Agent} sub={exchangedClaims.Sub}");
            Assert.Equal(Env("AUTHFI_LIVE_B_ID"), exchanged.Agent);
        }
        catch (AuthFIRefusedException e)
        {
            _out.WriteLine($"EXCHANGE refused without a delegation: {e.GetType().Name} code={e.Code} status={e.Status}");
            Assert.Equal("access_denied", e.Code);
            Assert.DoesNotContain(owner.Reveal(), e.ToString());
        }
    }

    [LiveFact]
    public async Task An_autonomous_agent_acting_for_a_person_is_refused_with_a_typed_error()
    {
        var person = new Secret(File.ReadAllText(Path.Combine(Env("AUTHFI_LIVE_DIR"), "user_api.tok")).Trim());
        var e = await Assert.ThrowsAnyAsync<AuthFIException>(() => A().ExchangeAsync(person, Env("AUTHFI_LIVE_API_AUDIENCE")));
        _out.WriteLine($"EXCHANGE by the autonomous agent refused: {e.GetType().Name} code={e.Code} status={e.Status}");
        Assert.DoesNotContain(person.Reveal(), e.ToString());
    }
}
