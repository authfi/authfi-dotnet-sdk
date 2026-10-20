using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace AuthFI;

/// <summary>What a verifier needs: the project issuer and the audience(s) of the API it protects.</summary>
public sealed class AuthFIVerifierOptions
{
    /// <summary>The project issuer, for example <c>https://acme.authfi.io</c>. Keys are found through its discovery document.</summary>
    public string Issuer { get; set; } = "";

    /// <summary>
    /// The audience(s) this API accepts: its own client id or resource identifier. Required. AuthFI's own
    /// audiences (the issuer, anything under it, the first-party client ids) are refused, because accepting one
    /// would let every gateway-bound agent token and delegated token be replayed at this API.
    /// </summary>
    public IList<string> Audiences { get; } = new List<string>();

    /// <summary>When set, a token whose <c>tenant_id</c> differs is refused. Set it when you know your tenant.</summary>
    public string? ExpectedTenantId { get; set; }

    /// <summary>Clock skew allowed on exp, nbf and iat, 0 to 300 seconds.</summary>
    public TimeSpan Leeway { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>How long a fetched key set is used before it is fetched again.</summary>
    public TimeSpan KeyCacheLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The least time between refetches caused by an unknown kid, so random kids cannot drive the key endpoint.</summary>
    public TimeSpan UnknownKidRefetchInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Optional. By default the verifier makes its own client: 10 s timeout, no redirects.</summary>
    public HttpClient? HttpClient { get; set; }

    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
}

/// <summary>
/// Verifies an AuthFI access token: a compact JWS whose <c>typ</c> is <c>at+jwt</c>, signed with RS256, PS256,
/// ES256 or EdDSA by a key the issuer publishes, issued by the configured issuer, for a configured audience,
/// and unexpired. An ID token, a token with no or unknown kid, or one using any other algorithm is refused.
/// </summary>
public sealed class AuthFIVerifier
{
    internal const int MaxTokenChars = 16 * 1024;

    private readonly string _issuer;
    private readonly HashSet<string> _audiences;
    private readonly string? _tenant;
    private readonly TimeSpan _leeway;
    private readonly TimeProvider _time;
    private readonly KeyStore _keys;

    public AuthFIVerifier(AuthFIVerifierOptions options)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));
        _issuer = NormaliseIssuer(options.Issuer);
        if (options.Audiences.Count == 0)
            throw new AuthFIConfigurationException(
                "An audience is required: the client id or resource identifier of the API this verifier protects.");
        foreach (var a in options.Audiences) RefuseOwnAudience(a, _issuer);
        _audiences = new HashSet<string>(options.Audiences, StringComparer.Ordinal);
        if (options.Leeway < TimeSpan.Zero || options.Leeway > TimeSpan.FromSeconds(300))
            throw new AuthFIConfigurationException("Leeway must be between 0 and 300 seconds.");
        if (options.KeyCacheLifetime <= TimeSpan.Zero || options.KeyCacheLifetime > TimeSpan.FromDays(1))
            throw new AuthFIConfigurationException("KeyCacheLifetime must be between 0 and 24 hours.");
        if (options.UnknownKidRefetchInterval < TimeSpan.Zero)
            throw new AuthFIConfigurationException("UnknownKidRefetchInterval must not be negative.");
        _leeway = options.Leeway;
        _tenant = string.IsNullOrEmpty(options.ExpectedTenantId) ? null : options.ExpectedTenantId;
        _time = options.TimeProvider ?? throw new AuthFIConfigurationException("A TimeProvider is required.");
        _keys = new KeyStore(_issuer, options.HttpClient, options.KeyCacheLifetime, options.UnknownKidRefetchInterval, _time);
    }

    public string Issuer => _issuer;

    public override string ToString() => $"AuthFIVerifier(issuer={_issuer})";

    /// <summary>Verify a Bearer access token. Throws <see cref="AuthFIException"/> with a stable code on any refusal.</summary>
    public AuthFIClaims Verify(string token) => Verify(new Secret(token ?? ""));

    public AuthFIClaims Verify(Secret token)
    {
        var jws = Jws.Parse(token?.Reveal() ?? "");
        var key = _keys.Find(jws.Kid);
        return Finish(jws, key);
    }

    public async Task<AuthFIClaims> VerifyAsync(string token, CancellationToken ct = default) =>
        await VerifyAsync(new Secret(token ?? ""), ct).ConfigureAwait(false);

    public async Task<AuthFIClaims> VerifyAsync(Secret token, CancellationToken ct = default)
    {
        var jws = Jws.Parse(token?.Reveal() ?? "");
        var key = await _keys.FindAsync(jws.Kid, ct).ConfigureAwait(false);
        return Finish(jws, key);
    }

    private AuthFIClaims Finish(Jws jws, VerificationKey? key)
    {
        using (jws.Payload)
        {
            if (key is null || !key.Algorithms.Contains(jws.Alg))
                throw new AuthFIException("token_key_unknown", "The issuer publishes no key for this token's kid and algorithm.", 401);
            if (!key.Verify(jws.Alg, jws.SigningInput, jws.Signature))
                throw new AuthFIException("token_signature_invalid", "The signature does not verify.", 401);
            try { return CheckClaims(jws.Payload.RootElement); }
            catch (InvalidOperationException) // a string claim holding an invalid escape cannot be read
            {
                throw new AuthFIException("token_claims_invalid", "A claim could not be read.", 401);
            }
        }
    }

    private AuthFIClaims CheckClaims(JsonElement c)
    {
        if (c.ValueKind != JsonValueKind.Object)
            throw new AuthFIException("token_malformed", "The payload is not a JSON object.", 401);

        if (!c.TryGetProperty("iss", out var iss) || iss.ValueKind != JsonValueKind.String
            || !string.Equals(iss.GetString(), _issuer, StringComparison.Ordinal))
            throw new AuthFIException("token_issuer_not_accepted", "The token was not issued by the configured issuer.", 401);

        var now = _time.GetUtcNow().ToUnixTimeSeconds();
        var leeway = (long)_leeway.TotalSeconds;

        var exp = Number(c, "exp") ?? throw new AuthFIException("token_claims_invalid", "exp is missing.", 401);
        if (now >= exp + leeway) throw new AuthFIException("token_expired", "The token has expired.", 401);
        var nbf = Number(c, "nbf");
        if (nbf is not null && nbf.Value > now + leeway)
            throw new AuthFIException("token_claims_invalid", "The token is not valid yet (nbf).", 401);
        var iat = Number(c, "iat");
        if (iat is not null && iat.Value > now + leeway)
            throw new AuthFIException("token_claims_invalid", "The token was issued in the future (iat).", 401);

        var aud = Audience(c);
        if (!aud.Any(_audiences.Contains))
            throw new AuthFIException("token_audience_mismatch", "The token is not for an audience this API accepts.", 401);

        var sub = Str(c, "sub");
        if (string.IsNullOrEmpty(sub)) throw new AuthFIException("token_claims_invalid", "sub is missing.", 401);
        var tenant = Str(c, "tenant_id");
        if (string.IsNullOrEmpty(tenant)) throw new AuthFIException("token_no_tenant", "The token names no tenant.", 401);
        if (_tenant is not null && !string.Equals(tenant, _tenant, StringComparison.Ordinal))
            throw new AuthFIException("token_tenant_not_issuers", "tenant_id is not the tenant this verifier is pinned to.", 401);

        string? actor = null;
        if (c.TryGetProperty("act", out var act) && act.ValueKind != JsonValueKind.Null)
        {
            if (act.ValueKind != JsonValueKind.Object)
                throw new AuthFIException("token_claims_invalid", "act is not an actor claim.", 401);
            if (act.TryGetProperty("act", out var inner) && inner.ValueKind != JsonValueKind.Null)
                throw new AuthFIException("token_act_chain_unsupported", "A chain of actors is not accepted.", 401);
            actor = Str(act, "sub");
        }
        if (Present(c, "cnf") || Present(c, "authfi_mandate"))
            throw new AuthFIException("token_dpop_proof_required", "A sender-constrained token was presented as a Bearer token.", 401);

        string orgId = Str(c, "org_id") ?? "";
        if (orgId.Length == 0 && c.TryGetProperty("custom", out var custom) && custom.ValueKind == JsonValueKind.Object)
            orgId = Str(custom, "org_id") ?? "";

        return new AuthFIClaims
        {
            Sub = sub,
            Email = Str(c, "email") ?? "",
            Name = Str(c, "name") ?? "",
            Roles = Strings(c, "roles"),
            Permissions = Strings(c, "permissions"),
            TenantId = tenant,
            OrgId = orgId,
            Exp = exp,
            Iat = iat ?? 0,
            Issuer = _issuer,
            Audience = aud,
            ClientId = Str(c, "client_id") ?? "",
            Scopes = Scopes(c),
            Jti = Str(c, "jti") ?? "",
            Actor = actor,
        };
    }

    private static bool Present(JsonElement c, string name) =>
        c.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null;

    private static string? Str(JsonElement c, string name)
    {
        if (!c.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null) return null;
        if (v.ValueKind != JsonValueKind.String)
            throw new AuthFIException("token_claims_invalid", $"{name} is not a string.", 401);
        return v.GetString();
    }

    private static long? Number(JsonElement c, string name)
    {
        if (!c.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null) return null;
        if (v.ValueKind != JsonValueKind.Number || !v.TryGetDouble(out var d) || double.IsNaN(d) || double.IsInfinity(d))
            throw new AuthFIException("token_claims_invalid", $"{name} is not a number.", 401);
        return (long)Math.Floor(d);
    }

    private static string[] Strings(JsonElement c, string name)
    {
        if (!c.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null) return Array.Empty<string>();
        if (v.ValueKind != JsonValueKind.Array)
            throw new AuthFIException("token_claims_invalid", $"{name} is not a list of strings.", 401);
        var list = new List<string>();
        foreach (var e in v.EnumerateArray())
        {
            if (e.ValueKind != JsonValueKind.String)
                throw new AuthFIException("token_claims_invalid", $"{name} is not a list of strings.", 401);
            list.Add(e.GetString()!);
        }
        return list.ToArray();
    }

    private static string[] Scopes(JsonElement c)
    {
        if (!c.TryGetProperty("scope", out var v) || v.ValueKind == JsonValueKind.Null) return Array.Empty<string>();
        if (v.ValueKind == JsonValueKind.String)
            return v.GetString()!.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return Strings(c, "scope");
    }

    private static string[] Audience(JsonElement c)
    {
        if (!c.TryGetProperty("aud", out var v) || v.ValueKind == JsonValueKind.Null)
            throw new AuthFIException("token_audience_mismatch", "The token has no audience.", 401);
        if (v.ValueKind == JsonValueKind.String) return new[] { v.GetString()! };
        return Strings(c, "aud");
    }

    private static string NormaliseIssuer(string issuer)
    {
        if (string.IsNullOrWhiteSpace(issuer) || issuer.Contains('@') || !Uri.TryCreate(issuer, UriKind.Absolute, out var u)
            || !string.IsNullOrEmpty(u.Query) || !string.IsNullOrEmpty(u.Fragment) || !string.IsNullOrEmpty(u.UserInfo)
            || u.AbsolutePath != "/")
            throw new AuthFIConfigurationException("The issuer must be an absolute URL such as https://acme.authfi.io, with no credentials, path or query.");
        if (u.Scheme != Uri.UriSchemeHttps && !(u.Scheme == Uri.UriSchemeHttp && u.IsLoopback))
            throw new AuthFIConfigurationException("The issuer must be an https URL.");
        return issuer.TrimEnd('/');
    }

    private static readonly string[] FirstPartyClients = { "authfi-console", "authfi-workspace" };

    private static void RefuseOwnAudience(string audience, string issuer)
    {
        const string fix = " Mint the token with resource=<your API's client id> and verify that audience.";
        if (string.IsNullOrWhiteSpace(audience))
            throw new AuthFIConfigurationException("An audience must not be empty.");
        if (FirstPartyClients.Contains(audience, StringComparer.OrdinalIgnoreCase))
            throw new AuthFIConfigurationException($"The audience '{audience}' is an AuthFI first-party client." + fix);
        var a = audience.TrimEnd('/');
        if (a == issuer || a.StartsWith(issuer + "/", StringComparison.Ordinal))
            throw new AuthFIConfigurationException("The audience is the issuer or a URL under it, which gateway tokens carry." + fix);
        if (Uri.TryCreate(audience, UriKind.Absolute, out var au))
        {
            var host = au.Host.ToLowerInvariant().TrimEnd('.'); // "api.authfi.io." is the same host
            if (string.Equals(au.Host, new Uri(issuer).Host, StringComparison.OrdinalIgnoreCase)
                || host == "authfi.io" || host.EndsWith(".authfi.io", StringComparison.Ordinal))
                throw new AuthFIConfigurationException("The audience is on AuthFI's own domain, which gateway tokens carry." + fix);
        }
    }
}

/// <summary>A parsed compact JWS whose header has passed every check that needs no key.</summary>
internal sealed class Jws
{
    public string Alg = "";
    public string Kid = "";
    public byte[] SigningInput = Array.Empty<byte>();
    public byte[] Signature = Array.Empty<byte>();
    public JsonDocument Payload = null!;

    private static readonly HashSet<string> Algs = new(StringComparer.Ordinal) { "RS256", "PS256", "ES256", "EdDSA" };

    public static Jws Parse(string raw)
    {
        if (string.IsNullOrEmpty(raw)) throw new AuthFIException("token_missing", "No credential.", 401);
        if (raw.Length > AuthFIVerifier.MaxTokenChars)
            throw new AuthFIException("token_malformed", "The token is too long.", 401);
        var parts = raw.Split('.');
        if (parts.Length == 5) throw new AuthFIException("token_malformed", "An encrypted token (JWE) is not an access token.", 401);
        if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length == 0)
            throw new AuthFIException("token_malformed", "Not a compact JWS of three parts.", 401);

        JsonElement header;
        JsonDocument headerDoc;
        try
        {
            var headerBytes = B64.Decode(parts[0]);
            if (Json.HasDuplicateName(headerBytes)) throw new FormatException();
            headerDoc = JsonDocument.Parse(headerBytes);
            header = headerDoc.RootElement;
        }
        catch (Exception e) when (e is FormatException or JsonException or ArgumentException or InvalidOperationException)
        {
            throw new AuthFIException("token_malformed", "The header is not base64url JSON.", 401);
        }

        using (headerDoc)
        {
            if (header.ValueKind != JsonValueKind.Object)
                throw new AuthFIException("token_malformed", "The header is not a JSON object.", 401);

            var alg = HeaderString(header, "alg");
            if (alg is null || !Algs.Contains(alg))
                throw new AuthFIException("token_signature_invalid", "The algorithm is not accepted.", 401);

            var typ = HeaderString(header, "typ");
            if (typ is null || !(typ.Equals("at+jwt", StringComparison.OrdinalIgnoreCase)
                                 || typ.Equals("application/at+jwt", StringComparison.OrdinalIgnoreCase)))
                throw new AuthFIException("token_not_access_token", "The token is not an access token (typ must be at+jwt).", 401);

            var kid = HeaderString(header, "kid");
            if (string.IsNullOrEmpty(kid)) throw new AuthFIException("token_key_unknown", "The token names no kid.", 401);

            if (header.TryGetProperty("crit", out _))
                throw new AuthFIException("token_claims_invalid", "The token requires an extension this verifier lacks (crit).", 401);

            byte[] sig;
            JsonDocument payload;
            try
            {
                sig = B64.Decode(parts[2]);
                var payloadBytes = B64.Decode(parts[1]);
                if (Json.HasDuplicateName(payloadBytes)) throw new FormatException();
                payload = JsonDocument.Parse(payloadBytes);
            }
            catch (Exception e) when (e is FormatException or JsonException or ArgumentException or InvalidOperationException)
            {
                throw new AuthFIException("token_malformed", "The token could not be decoded.", 401);
            }

            return new Jws
            {
                Alg = alg,
                Kid = kid,
                SigningInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]),
                Signature = sig,
                Payload = payload,
            };
        }
    }

    private static string? HeaderString(JsonElement header, string name)
    {
        if (!header.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.String) return null;
        try { return v.GetString(); }
        catch (InvalidOperationException) { throw new AuthFIException("token_malformed", "The header is not base64url JSON.", 401); }
    }
}

internal static class B64
{
    /// <summary>Decodes unpadded base64url and refuses anything but its canonical spelling, so one token is one string.</summary>
    public static byte[] Decode(string s)
    {
        if (s.Contains('=')) throw new FormatException();
        var t = s.Replace('-', '+').Replace('_', '/');
        switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; case 1: throw new FormatException(); }
        var bytes = Convert.FromBase64String(t);
        if (Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') != s) throw new FormatException();
        return bytes;
    }
}

internal static class Json
{
    /// <summary>True when an object at the top level repeats a property name; another parser would take the other value.</summary>
    public static bool HasDuplicateName(byte[] utf8)
    {
        var reader = new Utf8JsonReader(utf8);
        var names = new HashSet<string>(StringComparer.Ordinal);
        var depth = 0;
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                case JsonTokenType.StartArray:
                    depth++;
                    break;
                case JsonTokenType.EndObject:
                case JsonTokenType.EndArray:
                    depth--;
                    break;
                case JsonTokenType.PropertyName when depth == 1:
                    if (!names.Add(reader.GetString()!)) return true;
                    break;
            }
        }
        return false;
    }
}

/// <summary>A published signing key, with the algorithms it may be used for.</summary>
internal sealed class VerificationKey
{
    public required string Kid { get; init; }
    public required HashSet<string> Algorithms { get; init; }
    public required Func<string, byte[], byte[], bool> Verify { get; init; }

    private static int BitLength(byte[] bigEndian)
    {
        var i = 0;
        while (i < bigEndian.Length && bigEndian[i] == 0) i++;
        return i == bigEndian.Length ? 0 : (bigEndian.Length - i - 1) * 8 + (32 - System.Numerics.BitOperations.LeadingZeroCount((uint)bigEndian[i]));
    }

    /// <summary>Builds the key from a JWK, or null when it is not a usable signature key.</summary>
    public static VerificationKey? FromJwk(JsonElement jwk)
    {
        try
        {
            if (jwk.ValueKind != JsonValueKind.Object) return null;
            foreach (var member in new[] { "kid", "kty", "use", "alg" })
                if (jwk.TryGetProperty(member, out var m) && m.ValueKind != JsonValueKind.String) return null; // a present non-string makes the key unusable
            string? S(string n) => jwk.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            var kid = S("kid");
            var kty = S("kty");
            if (string.IsNullOrEmpty(kid) || kty is null) return null;
            var use = S("use");
            if (use is not null && use != "sig") return null;
            var declared = S("alg");

            HashSet<string> allowed;
            Func<string, byte[], byte[], bool> verify;
            switch (kty)
            {
                case "RSA":
                {
                    var modulus = B64.Decode(S("n") ?? "");
                    if (BitLength(modulus) < 2048) return null;
                    var rsa = RSA.Create();
                    rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = B64.Decode(S("e") ?? "") });
                    allowed = new() { "RS256", "PS256" };
                    verify = (alg, data, sig) => rsa.VerifyData(data, sig, HashAlgorithmName.SHA256,
                        alg == "PS256" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
                    break;
                }
                case "EC":
                {
                    if (S("crv") != "P-256") return null;
                    var ec = ECDsa.Create(new ECParameters
                    {
                        Curve = ECCurve.NamedCurves.nistP256,
                        Q = new ECPoint { X = B64.Decode(S("x") ?? ""), Y = B64.Decode(S("y") ?? "") },
                    });
                    allowed = new() { "ES256" };
                    verify = (_, data, sig) => sig.Length == 64 && ec.VerifyData(data, sig, HashAlgorithmName.SHA256,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                    break;
                }
                case "OKP":
                {
                    if (S("crv") != "Ed25519") return null;
                    var x = B64.Decode(S("x") ?? "");
                    if (x.Length != 32) return null;
                    var pub = new Ed25519PublicKeyParameters(x, 0);
                    allowed = new() { "EdDSA" };
                    verify = (_, data, sig) =>
                    {
                        if (sig.Length != 64) return false;
                        var signer = new Ed25519Signer();
                        signer.Init(false, pub);
                        signer.BlockUpdate(data, 0, data.Length);
                        return signer.VerifySignature(sig);
                    };
                    break;
                }
                default:
                    return null;
            }

            if (declared is not null)
            {
                if (!allowed.Contains(declared)) return null;
                allowed = new() { declared };
            }
            return new VerificationKey { Kid = kid, Algorithms = allowed, Verify = verify };
        }
        catch (Exception e) when (e is CryptographicException or FormatException or ArgumentException or JsonException or InvalidOperationException)
        {
            return null;
        }
    }
}

/// <summary>
/// The issuer's key set, found through its discovery document. Fetched on first use and again after the lifetime.
/// An unknown kid refetches at most once per interval, a failed fetch is not retried for a few seconds, and callers
/// share one fetch in flight, so neither random kids nor an outage can drive the issuer's key endpoint.
/// </summary>
internal sealed class KeyStore
{
    private const int MaxBytes = 1 << 20;
    private static readonly TimeSpan FailureBackoff = TimeSpan.FromSeconds(5);

    private readonly string _issuer;
    private readonly string _scheme;
    private readonly string _host;
    private readonly HttpClient _http;
    private readonly TimeSpan _lifetime;
    private readonly TimeSpan _unknownKidInterval;
    private readonly TimeProvider _time;
    private readonly object _lock = new();
    private readonly SemaphoreSlim _gate = new(1, 1);

    private Dictionary<string, VerificationKey>? _byKid;
    private DateTimeOffset _fetchedAt;
    private DateTimeOffset _attemptedAt;
    private bool _lastFailed;

    public KeyStore(string issuer, HttpClient? http, TimeSpan lifetime, TimeSpan unknownKidInterval, TimeProvider time)
    {
        _issuer = issuer;
        _scheme = new Uri(issuer).Scheme;
        _host = new Uri(issuer).Host;
        _http = http ?? new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(10) };
        _lifetime = lifetime;
        _unknownKidInterval = unknownKidInterval;
        _time = time;
    }

    public VerificationKey? Find(string kid)
    {
        if (Answerable(kid, out var key)) return key;
        _gate.Wait();
        try
        {
            if (Answerable(kid, out key)) return key; // another caller refreshed while this one waited
            Attempt();
            try { Apply(Fetch(sync: true, default).GetAwaiter().GetResult()); }
            catch { Failed(); throw; }
            return Lookup(kid);
        }
        finally { _gate.Release(); }
    }

    public async Task<VerificationKey?> FindAsync(string kid, CancellationToken ct)
    {
        if (Answerable(kid, out var key)) return key;
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (Answerable(kid, out key)) return key;
            var before = Attempt();
            try { Apply(await Fetch(sync: false, ct).ConfigureAwait(false)); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { Undo(before); throw; } // the caller left; the issuer did not fail
            catch { Failed(); throw; }
            return Lookup(kid);
        }
        finally { _gate.Release(); }
    }

    /// <summary>True when the cache answers (a key, or null for a kid not worth a refetch yet); false when a fetch is due. Throws while backing off after a failure.</summary>
    private bool Answerable(string kid, out VerificationKey? key)
    {
        lock (_lock)
        {
            key = null;
            var now = _time.GetUtcNow();
            var sinceAttempt = now - _attemptedAt;
            var attemptedRecently = sinceAttempt >= TimeSpan.Zero && sinceAttempt < FailureBackoff;
            if (_byKid is not null)
            {
                var age = now - _fetchedAt; // a clock that stepped back counts as expired
                if (age >= TimeSpan.Zero && age < _lifetime)
                {
                    if (_byKid.TryGetValue(kid, out key)) return true;
                    return sinceAttempt >= TimeSpan.Zero && sinceAttempt < _unknownKidInterval;
                }
            }
            if (_lastFailed && attemptedRecently)
                throw new AuthFIException("jwks_unavailable", "The issuer's keys could not be fetched.", 503);
            return false;
        }
    }

    private DateTimeOffset Attempt()
    {
        lock (_lock)
        {
            var before = _attemptedAt;
            _attemptedAt = _time.GetUtcNow();
            return before;
        }
    }

    private void Undo(DateTimeOffset attemptedAt) { lock (_lock) _attemptedAt = attemptedAt; }

    private void Failed() { lock (_lock) _lastFailed = true; }

    private VerificationKey? Lookup(string kid)
    {
        lock (_lock) return _byKid is not null && _byKid.TryGetValue(kid, out var k) ? k : null;
    }

    private void Apply(Dictionary<string, VerificationKey> keys)
    {
        lock (_lock)
        {
            _byKid = keys;
            _fetchedAt = _time.GetUtcNow();
            _lastFailed = false;
        }
    }

    private async Task<Dictionary<string, VerificationKey>> Fetch(bool sync, CancellationToken ct)
    {
        try
        {
            var meta = await Get(_issuer + "/.well-known/oauth-authorization-server", sync, ct).ConfigureAwait(false);
            string jwksUri;
            using (var doc = JsonDocument.Parse(meta))
            {
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object
                    || !root.TryGetProperty("issuer", out var iss) || iss.ValueKind != JsonValueKind.String
                    || iss.GetString()!.TrimEnd('/') != _issuer
                    || !root.TryGetProperty("jwks_uri", out var ju) || ju.ValueKind != JsonValueKind.String)
                    throw new AuthFIException("jwks_unavailable", "The discovery document does not belong to this issuer.", 503);
                jwksUri = ju.GetString()!;
            }
            if (!Uri.TryCreate(jwksUri, UriKind.Absolute, out var u) || u.Scheme != _scheme || !string.IsNullOrEmpty(u.UserInfo)
                || !string.Equals(u.Host, _host, StringComparison.OrdinalIgnoreCase))
                throw new AuthFIException("jwks_unavailable", "The discovery document's jwks_uri is not on the issuer's scheme and host.", 503);

            var json = await Get(jwksUri, sync, ct).ConfigureAwait(false);
            var byKid = new Dictionary<string, VerificationKey>(StringComparer.Ordinal);
            var dup = new HashSet<string>(StringComparer.Ordinal);
            using (var doc = JsonDocument.Parse(json))
            {
                if (doc.RootElement.ValueKind != JsonValueKind.Object
                    || !doc.RootElement.TryGetProperty("keys", out var arr) || arr.ValueKind != JsonValueKind.Array)
                    throw new AuthFIException("jwks_unavailable", "The key set is malformed.", 503);
                foreach (var jwk in arr.EnumerateArray())
                {
                    var k = VerificationKey.FromJwk(jwk);
                    if (k is null) continue;
                    if (!byKid.TryAdd(k.Kid, k)) dup.Add(k.Kid);
                }
            }
            foreach (var d in dup) byKid.Remove(d); // one kid, two keys: ambiguous, so neither is used
            return byKid;
        }
        catch (AuthFIException) { throw; }
        catch (Exception e) when (!(e is OperationCanceledException && ct.IsCancellationRequested))
        {
            // Whatever the transport raised (including a handler's own bug), the caller sees one refusal that names no input.
            throw new AuthFIException("jwks_unavailable", "The issuer's keys could not be fetched.", 503);
        }
    }

    private async Task<string> Get(string url, bool sync, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        using var res = sync ? _http.Send(req, HttpCompletionOption.ResponseHeadersRead, ct)
                             : await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
            throw new AuthFIException("jwks_unavailable", $"The issuer answered {(int)res.StatusCode} for its key metadata.", 503);
        using var s = sync ? res.Content.ReadAsStream(ct) : await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buf = new byte[8192];
        int n;
        while ((n = sync ? s.Read(buf, 0, buf.Length) : await s.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
        {
            ms.Write(buf, 0, n);
            if (ms.Length > MaxBytes) throw new AuthFIException("jwks_unavailable", "The key metadata is too large.", 503);
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }
}
