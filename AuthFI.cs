using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;

namespace AuthFI;

/// <summary>
/// AuthFI .NET SDK
///
/// Usage (ASP.NET Core):
///   var auth = new AuthFIClient("https://acme.authfi.io", audience: "api_orders");
///
///   app.MapGet("/api/users", (HttpContext ctx) => {
///       var user = auth.Authenticate(ctx);
///       auth.RequirePermissions(user, "read:users");
///       return Results.Ok(users);
///   });
/// </summary>
public class AuthFIClient
{
    private readonly AuthFIVerifier _verifier;

    /// <param name="issuer">The project issuer, for example <c>https://acme.authfi.io</c>.</param>
    /// <param name="audience">The client id or resource identifier of the API this client protects.</param>
    public AuthFIClient(string issuer, string audience)
        : this(OptionsFor(issuer, audience))
    {
    }

    public AuthFIClient(AuthFIVerifierOptions options)
    {
        _verifier = new AuthFIVerifier(options);
    }

    public AuthFIVerifier Verifier => _verifier;

    public override string ToString() => $"AuthFIClient(issuer={_verifier.Issuer})";

    private static AuthFIVerifierOptions OptionsFor(string issuer, string audience)
    {
        var o = new AuthFIVerifierOptions { Issuer = issuer };
        o.Audiences.Add(audience);
        return o;
    }

    /// <summary>Authenticate request and return decoded claims.</summary>
    public AuthFIClaims Authenticate(HttpContext context)
    {
        var auth = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(auth))
            throw new AuthFIException("token_missing", "Missing authorization", 401);
        if (auth.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
            throw new AuthFIException("token_dpop_unsupported", "DPoP-bound tokens are not supported.", 401);
        if (!auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            throw new AuthFIException("token_missing", "Missing authorization", 401);

        return VerifyToken(auth[7..].Trim());
    }

    /// <summary>
    /// Verify an access token and return its claims. See <see cref="AuthFIVerifier"/> for what is checked.
    /// Any failure throws <see cref="AuthFIException"/>.
    /// </summary>
    public AuthFIClaims VerifyToken(string token) => _verifier.Verify(token);

    public Task<AuthFIClaims> VerifyTokenAsync(string token, CancellationToken ct = default) =>
        _verifier.VerifyAsync(token, ct);

    /// <summary>Check ALL permissions present.</summary>
    public void RequirePermissions(AuthFIClaims user, params string[] permissions)
    {
        var userPerms = new HashSet<string>(user.Permissions ?? Array.Empty<string>());
        var missing = permissions.Where(p => !userPerms.Contains(p)).ToList();

        if (missing.Count > 0)
            throw new AuthFIException("insufficient_permission", $"Missing permissions: {string.Join(", ", missing)}", 403);
    }

    /// <summary>Check ANY role matches.</summary>
    public void RequireRole(AuthFIClaims user, params string[] roles)
    {
        var userRoles = new HashSet<string>(user.Roles ?? Array.Empty<string>());
        if (!roles.Any(r => userRoles.Contains(r)))
            throw new AuthFIException("insufficient_role", "Insufficient role", 403);
    }
}

/// <summary>The claims of a verified access token. It keeps no raw token.</summary>
public class AuthFIClaims
{
    [JsonPropertyName("sub")]
    public string Sub { get; set; } = "";

    [JsonPropertyName("email")]
    public string Email { get; set; } = "";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("roles")]
    public string[] Roles { get; set; } = Array.Empty<string>();

    [JsonPropertyName("permissions")]
    public string[] Permissions { get; set; } = Array.Empty<string>();

    [JsonPropertyName("tenant_id")]
    public string TenantId { get; set; } = "";

    [JsonPropertyName("org_id")]
    public string OrgId { get; set; } = "";

    [JsonPropertyName("exp")]
    public long Exp { get; set; }

    [JsonPropertyName("iat")]
    public long Iat { get; set; }

    [JsonPropertyName("iss")]
    public string Issuer { get; set; } = "";

    [JsonPropertyName("aud")]
    public string[] Audience { get; set; } = Array.Empty<string>();

    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = "";

    [JsonPropertyName("scope")]
    public string[] Scopes { get; set; } = Array.Empty<string>();

    [JsonPropertyName("jti")]
    public string Jti { get; set; } = "";

    /// <summary>The subject of <c>act</c>: who is acting for the subject (an agent), or null.</summary>
    [JsonPropertyName("act_sub")]
    public string? Actor { get; set; }

    public override string ToString() => $"AuthFIClaims(sub={Sub}, tenant={TenantId})";
}
