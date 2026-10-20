using Xunit;
using Xunit.Abstractions;

namespace AuthFI.Tests;

/// <summary>Skipped unless AUTHFI_LIVE_ISSUER is set. Runs the verifier against a real project's tokens.</summary>
public sealed class LiveFactAttribute : FactAttribute
{
    public LiveFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AUTHFI_LIVE_ISSUER")))
            Skip = "set AUTHFI_LIVE_ISSUER (and the token files) to run against a live project";
    }
}

/// <summary>
/// Env: AUTHFI_LIVE_ISSUER, AUTHFI_LIVE_TENANT, AUTHFI_LIVE_DIR (holds user_api.tok, agent.tok, id_api.tok),
/// AUTHFI_LIVE_WEB_AUDIENCE (the front end's client id, the aud of the user and ID tokens),
/// AUTHFI_LIVE_API_AUDIENCE (the API's client id, the aud of the agent token).
/// Token values are never printed.
/// </summary>
public class LiveTests
{
    private readonly ITestOutputHelper _out;
    public LiveTests(ITestOutputHelper output) => _out = output;

    private static string Env(string n) => Environment.GetEnvironmentVariable(n) ?? throw new InvalidOperationException(n + " is not set");
    private static string Tok(string name) => File.ReadAllText(Path.Combine(Env("AUTHFI_LIVE_DIR"), name + ".tok")).Trim();

    private AuthFIVerifier Verifier(string audience, string? tenant = null)
    {
        var o = new AuthFIVerifierOptions { Issuer = Env("AUTHFI_LIVE_ISSUER"), ExpectedTenantId = tenant ?? Env("AUTHFI_LIVE_TENANT") };
        o.Audiences.Add(audience);
        return new AuthFIVerifier(o);
    }

    [LiveFact]
    public async Task An_RS256_user_token_is_accepted()
    {
        var c = await Verifier(Env("AUTHFI_LIVE_WEB_AUDIENCE")).VerifyAsync(Tok("user_api"));
        _out.WriteLine($"ACCEPTED RS256 user token: sub={c.Sub} tenant={c.TenantId} aud={string.Join(",", c.Audience)} client={c.ClientId}");
        Assert.Equal(Env("AUTHFI_LIVE_TENANT"), c.TenantId);
        Assert.Contains(Env("AUTHFI_LIVE_WEB_AUDIENCE"), c.Audience);
    }

    [LiveFact]
    public async Task An_EdDSA_agent_token_is_accepted()
    {
        var c = await Verifier(Env("AUTHFI_LIVE_API_AUDIENCE")).VerifyAsync(Tok("agent"));
        _out.WriteLine($"ACCEPTED EdDSA agent token: sub={c.Sub} tenant={c.TenantId} aud={string.Join(",", c.Audience)} client={c.ClientId}");
        Assert.StartsWith("agt_", c.Sub);
    }

    [LiveFact]
    public async Task An_ID_token_is_refused_as_an_access_token()
    {
        var e = await Assert.ThrowsAsync<AuthFIException>(() => Verifier(Env("AUTHFI_LIVE_WEB_AUDIENCE")).VerifyAsync(Tok("id_api")));
        _out.WriteLine($"REFUSED ID token: {e.Code} ({e.Status})");
        Assert.Equal("token_not_access_token", e.Code);
    }

    [LiveFact]
    public async Task Controls_the_same_tokens_are_refused_when_anything_else_is_wrong()
    {
        // The agent token is for the API; this verifier protects the web app.
        var e1 = await Assert.ThrowsAsync<AuthFIException>(() => Verifier(Env("AUTHFI_LIVE_WEB_AUDIENCE")).VerifyAsync(Tok("agent")));
        _out.WriteLine($"REFUSED agent token at the wrong audience: {e1.Code}");
        Assert.Equal("token_audience_mismatch", e1.Code);

        var e2 = await Assert.ThrowsAsync<AuthFIException>(() => Verifier(Env("AUTHFI_LIVE_WEB_AUDIENCE"), "00000000-0000-0000-0000-000000000000").VerifyAsync(Tok("user_api")));
        _out.WriteLine($"REFUSED user token pinned to another tenant: {e2.Code}");
        Assert.Equal("token_tenant_not_issuers", e2.Code);

        var parts = Tok("user_api").Split('.');
        var sig = parts[2].ToCharArray();
        sig[10] = sig[10] == 'A' ? 'B' : 'A';
        var e3 = await Assert.ThrowsAsync<AuthFIException>(() => Verifier(Env("AUTHFI_LIVE_WEB_AUDIENCE")).VerifyAsync(parts[0] + "." + parts[1] + "." + new string(sig)));
        _out.WriteLine($"REFUSED user token with one signature character changed: {e3.Code}");
        Assert.Equal("token_signature_invalid", e3.Code);

        var e4 = Assert.Throws<AuthFIConfigurationException>(() => Verifier("authfi-console"));
        _out.WriteLine($"REFUSED to configure AuthFI's own audience: {e4.GetType().Name}");

        var e5 = await Assert.ThrowsAsync<AuthFIException>(() => Verifier(Env("AUTHFI_LIVE_API_AUDIENCE")).VerifyAsync(Tok("user_api")));
        Assert.Equal("token_audience_mismatch", e5.Code);
    }
}
