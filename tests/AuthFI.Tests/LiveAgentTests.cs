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

        var person = new Secret(File.ReadAllText(Path.Combine(Env("AUTHFI_LIVE_DIR"), "user_api.tok")).Trim());
        try
        {
            var t = await agent.ExchangeAsync(person, resource);
            _out.WriteLine($"EXCHANGED: person={t.Person} agent={t.Agent}");
            Assert.Equal(Env("AUTHFI_LIVE_B_ID"), t.Agent);
        }
        catch (AuthFIException e)
        {
            _out.WriteLine($"EXCHANGE refused: {e.GetType().Name} code={e.Code} status={e.Status}");
            Assert.DoesNotContain(person.Reveal(), e.ToString());
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
