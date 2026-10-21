using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthFI.Agents;

public sealed class AgentAuthOptions
{
    /// <summary>The project issuer, for example <c>https://acme.authfi.io</c>. There is no default platform URL.</summary>
    public string Issuer { get; set; } = "";
    public string AgentId { get; set; } = "";
    public AgentKey? Key { get; set; }
    /// <summary>Optional. By default the agent makes its own client: 15 s timeout, no redirects, pooled connections recycled after 2 minutes.</summary>
    public HttpClient? HttpClient { get; set; }
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
    /// <summary>How <see cref="AgentAuth.AwaitUserTokenAsync"/> waits between polls. Tests replace it.</summary>
    public Func<TimeSpan, CancellationToken, Task> Delay { get; set; } = (d, ct) => Task.Delay(d, ct);
}

/// <summary>A person's pending approval of an agent acting for them (CIBA, poll mode).</summary>
public sealed class CibaRequest
{
    internal CibaRequest(Secret authReqId, DateTimeOffset expiresAt, TimeSpan interval, DateTimeOffset nextPollAt, string? approvalUrl)
    {
        AuthReqId = authReqId; ExpiresAt = expiresAt; Interval = interval; NextPollAt = nextPollAt; ApprovalUrl = approvalUrl;
    }

    internal Secret AuthReqId { get; }
    internal SemaphoreSlim PollGate { get; } = new(1, 1);
    public DateTimeOffset ExpiresAt { get; }
    public TimeSpan Interval { get; internal set; }
    /// <summary>The earliest moment the next poll may be sent; an earlier <see cref="AgentAuth.PollAsync"/> sends nothing.</summary>
    public DateTimeOffset NextPollAt { get; internal set; }
    public string? ApprovalUrl { get; }

    public override string ToString() => $"CibaRequest(expires_at={ExpiresAt:O}, interval={Interval.TotalSeconds}s)";
}

/// <summary>A token whose subject is a person and whose actor is the agent.</summary>
public sealed class DelegatedToken
{
    internal DelegatedToken(Secret token, DateTimeOffset expiresAt, string person, string agent, string[] scopes)
    {
        Token = token; ExpiresAt = expiresAt; Person = person; Agent = agent; Scopes = scopes;
    }

    public Secret Token { get; }
    public DateTimeOffset ExpiresAt { get; }
    /// <summary>The person, without a <c>user:</c> prefix.</summary>
    public string Person { get; }
    /// <summary>The agent, without an <c>agent:</c> prefix.</summary>
    public string Agent { get; }
    public string[] Scopes { get; }

    public override string ToString() => $"DelegatedToken(person={Person}, agent={Agent}, expires_at={ExpiresAt:O})";
}

/// <summary>
/// An agent's own credentials: its access token (private_key_jwt, cached until a minute before it expires),
/// and acting for a person by CIBA and token exchange. Tokens are <see cref="Secret"/> values.
/// </summary>
public sealed class AgentAuth
{
    private static readonly TimeSpan SlowDownStep = TimeSpan.FromSeconds(5);
    private const string JwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private const string CibaGrant = "urn:openid:params:grant-type:ciba";
    private const string ExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

    private readonly string _issuer;
    private readonly Uri _origin;
    private readonly string _agentId;
    private readonly AgentKey _key;
    private readonly HttpClient _http;
    private readonly TimeProvider _time;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly SemaphoreSlim _mint = new(1, 1);
    private readonly Dictionary<string, (Secret Token, DateTimeOffset RefreshAt)> _cache = new();
    private sealed record Meta(string TokenEndpoint, string? Ciba, DateTimeOffset At);
    private volatile Meta? _meta;
    private volatile string? _approvalEndpoint;

    public AgentAuth(AgentAuthOptions options)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));
        if (string.IsNullOrWhiteSpace(options.Issuer) || options.Issuer.Contains('@') || !Uri.TryCreate(options.Issuer, UriKind.Absolute, out var u)
            || !(u.Scheme == Uri.UriSchemeHttps || (u.Scheme == Uri.UriSchemeHttp && u.IsLoopback)))
            throw new AuthFIConfigurationException("The issuer must be the project's https URL, for example https://acme.authfi.io.");
        if (string.IsNullOrWhiteSpace(options.AgentId)) throw new AuthFIConfigurationException("The agent id is required.");
        _issuer = options.Issuer.TrimEnd('/');
        _origin = new Uri(_issuer);
        _agentId = options.AgentId;
        _key = options.Key ?? throw new AuthFIConfigurationException("The agent key is required.");
        _time = options.TimeProvider;
        _delay = options.Delay;
        _http = options.HttpClient ?? new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        }) { Timeout = TimeSpan.FromSeconds(15) };
    }

    /// <summary>AUTHFI_ISSUER, AUTHFI_AGENT_ID and the key from AUTHFI_AGENT_KEY (PEM) or AUTHFI_AGENT_KEY_FILE; AUTHFI_AGENT_KEY_ID names its kid.</summary>
    public static AgentAuth FromEnvironment()
    {
        string Need(string n) => Environment.GetEnvironmentVariable(n) is { Length: > 0 } v ? v
            : throw new AuthFIConfigurationException($"{n} is not set.");
        var pem = Environment.GetEnvironmentVariable("AUTHFI_AGENT_KEY");
        if (string.IsNullOrEmpty(pem))
        {
            var file = Environment.GetEnvironmentVariable("AUTHFI_AGENT_KEY_FILE");
            if (string.IsNullOrEmpty(file)) throw new AuthFIConfigurationException("Set AUTHFI_AGENT_KEY or AUTHFI_AGENT_KEY_FILE.");
            if (!File.Exists(file)) throw new AuthFIConfigurationException("AUTHFI_AGENT_KEY_FILE names no file.");
            if (!OperatingSystem.IsWindows()
                && (File.GetUnixFileMode(file) & (UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                                                  | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
                throw new AuthFIConfigurationException("The agent key file is open to others; allow at most read for its owner's group (chmod 600 or 640).");
            pem = File.ReadAllText(file);
        }
        return new AgentAuth(new AgentAuthOptions
        {
            Issuer = Need("AUTHFI_ISSUER"),
            AgentId = Need("AUTHFI_AGENT_ID"),
            Key = AgentKey.Load(pem, Environment.GetEnvironmentVariable("AUTHFI_AGENT_KEY_ID")),
        });
    }

    public string AgentId => _agentId;

    public override string ToString() => $"AgentAuth(issuer={_issuer}, agent={_agentId}, key={_key})";

    /// <summary>The agent's access token, cached until 60 seconds before it expires. <paramref name="resource"/> names the API it is for.</summary>
    public async Task<Secret> GetTokenAsync(string? resource = null, CancellationToken ct = default)
    {
        var cacheKey = resource ?? "";
        await _mint.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_cache.TryGetValue(cacheKey, out var hit) && _time.GetUtcNow() < hit.RefreshAt) return hit.Token;
            var meta = await MetaAsync(ct).ConfigureAwait(false);
            Dictionary<string, string> MintForm()
            {
                var f = ClientAuth(meta.TokenEndpoint); // a retry signs a fresh assertion: a replayed jti is refused
                f["grant_type"] = "client_credentials";
                if (!string.IsNullOrEmpty(resource)) f["resource"] = resource;
                return f;
            }
            using var body = await PostFormAsync(meta.TokenEndpoint, MintForm, retryOnReset: true, ct).ConfigureAwait(false);
            var token = TokenFrom(body, out var expiresIn);
            if (_cache.Count >= 64 && !_cache.ContainsKey(cacheKey))
            {
                var now = _time.GetUtcNow();
                foreach (var stale in _cache.Where(c => c.Value.RefreshAt <= now).Select(c => c.Key).ToList()) _cache.Remove(stale);
                if (_cache.Count >= 64) _cache.Remove(_cache.OrderBy(c => c.Value.RefreshAt).First().Key);
            }
            _cache[cacheKey] = (token, _time.GetUtcNow().AddSeconds(expiresIn - 60));
            return token;
        }
        finally { _mint.Release(); }
    }

    /// <summary>Drops the cached token for <paramref name="resource"/>, so the next call mints a fresh one. The gateway calls this when it refuses a token.</summary>
    public async Task ForgetTokenAsync(string? resource = null, Secret? refused = null, CancellationToken ct = default)
    {
        await _mint.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // A late refusal of an old token must not evict a newer one minted meanwhile.
            if (_cache.TryGetValue(resource ?? "", out var hit) && (refused is null || hit.Token.ValueEquals(refused)))
                _cache.Remove(resource ?? "");
        }
        finally { _mint.Release(); }
    }

    /// <summary>Asks a person, on their own device, to let this agent act for them. The agent never sees a code.</summary>
    public async Task<CibaRequest> BackchannelAuthorizeAsync(string loginHint, string bindingMessage,
        IEnumerable<string>? scope = null, int? expiresIn = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(loginHint))
            throw new AuthFIConfigurationException("login_hint is required: the platform must know which person to ask.");
        if (string.IsNullOrWhiteSpace(bindingMessage))
            throw new AuthFIConfigurationException("binding_message is required: it is what the person reads on their own device.");
        if (expiresIn is <= 0) throw new AuthFIConfigurationException("expires_in must be a positive number of seconds.");
        var meta = await MetaAsync(ct).ConfigureAwait(false);
        var endpoint = meta.Ciba ?? throw new AuthFIException("ciba_unavailable", "The issuer publishes no backchannel authentication endpoint.", 501);
        var form = ClientAuth(meta.TokenEndpoint);
        form["login_hint"] = loginHint.Trim();
        form["binding_message"] = bindingMessage.Trim();
        var scopeText = Join(scope);
        if (scopeText is not null) form["scope"] = scopeText;
        if (expiresIn is not null) form["requested_expiry"] = expiresIn.Value.ToString();

        using var body = await PostFormAsync(endpoint, () => form, retryOnReset: false, ct).ConfigureAwait(false);
        var root = body.RootElement;
        var id = Str(root, "auth_req_id");
        if (string.IsNullOrEmpty(id)) throw new AuthFIException("invalid_response", "The backchannel endpoint answered no auth_req_id.", 502);
        var now = _time.GetUtcNow();
        var interval = TimeSpan.FromSeconds(Num(root, "interval") is > 0 and var i ? i : 5);
        var lifetime = Num(root, "expires_in") is > 0 and var e ? e : 300;
        var approvalUrl = Str(root, "approval_url");
        return new CibaRequest(new Secret(id), now.AddSeconds(lifetime), interval, now + interval,
            approvalUrl is not null && OnIssuerOrigin(approvalUrl) ? new Uri(approvalUrl).AbsoluteUri : null);
    }

    /// <summary>
    /// One non-blocking poll. Returns null while the person has not decided, and sends nothing before
    /// <see cref="CibaRequest.NextPollAt"/>. <c>slow_down</c> widens the interval by five seconds.
    /// </summary>
    public async Task<DelegatedToken?> PollAsync(CibaRequest request, string? resource = null, CancellationToken ct = default) =>
        (await PollCoreAsync(request, resource, ct).ConfigureAwait(false)).Token;

    private async Task<(DelegatedToken? Token, bool Busy)> PollCoreAsync(CibaRequest request, string? resource, CancellationToken ct)
    {
        if (!await request.PollGate.WaitAsync(0, ct).ConfigureAwait(false)) return (null, true); // a poll for this request is already on its way
        try
        {
            var now = _time.GetUtcNow();
            if (now >= request.ExpiresAt) throw new AuthFIException("expired_token", "The person did not decide before the request expired.", 400);
            if (now < request.NextPollAt) return (null, false);
            var meta = await MetaAsync(ct).ConfigureAwait(false);
            var form = ClientAuth(meta.TokenEndpoint);
            form["grant_type"] = CibaGrant;
            form["auth_req_id"] = request.AuthReqId.Reveal();
            if (!string.IsNullOrEmpty(resource)) form["resource"] = resource;
            try
            {
                using var body = await PostFormAsync(meta.TokenEndpoint, () => form, retryOnReset: false, ct).ConfigureAwait(false);
                return (Delegated(body), false);
            }
            catch (AuthFIException e) when (e.Code == "authorization_pending")
            {
                request.NextPollAt = _time.GetUtcNow() + request.Interval;
                return (null, false);
            }
            catch (AuthFIException e) when (e.Code == "slow_down")
            {
                request.Interval += SlowDownStep;
                request.NextPollAt = _time.GetUtcNow() + request.Interval;
                return (null, false);
            }
        }
        finally { request.PollGate.Release(); }
    }

    /// <summary>Polls at the request's pace until the person decides. A denial or expiry throws; running out of time throws authorization_pending.</summary>
    public async Task<DelegatedToken> AwaitUserTokenAsync(CibaRequest request, TimeSpan? timeout = null, string? resource = null,
        CancellationToken ct = default)
    {
        var deadline = _time.GetUtcNow() + (timeout ?? TimeSpan.FromMinutes(5));
        while (true)
        {
            var wait = request.NextPollAt - _time.GetUtcNow();
            if (wait < TimeSpan.Zero) wait = TimeSpan.Zero;
            if (_time.GetUtcNow() + wait > deadline)
                throw new AuthFIException("authorization_pending",
                    "The person had not decided in time; the request may still be open.", 408);
            if (wait > TimeSpan.Zero) await _delay(wait, ct).ConfigureAwait(false);
            var (token, busy) = await PollCoreAsync(request, resource, ct).ConfigureAwait(false);
            if (token is not null) return token;
            if (busy) await _delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false); // another caller's poll is in flight; do not spin
        }
    }

    /// <summary>
    /// RFC 8693: the person's token in, a token whose subject is the person and whose actor is this agent out.
    /// The agent authenticates through its own access token; no client credentials are sent.
    /// </summary>
    public async Task<DelegatedToken> ExchangeAsync(Secret subjectToken, string? resource = null,
        IEnumerable<string>? scope = null, CancellationToken ct = default)
    {
        if (subjectToken is null) throw new ArgumentNullException(nameof(subjectToken));
        var actor = await GetTokenAsync(null, ct).ConfigureAwait(false);
        var meta = await MetaAsync(ct).ConfigureAwait(false);
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = ExchangeGrant,
            ["subject_token"] = subjectToken.Reveal(),
            ["subject_token_type"] = AccessTokenType,
            ["actor_token"] = actor.Reveal(),
            ["actor_token_type"] = AccessTokenType,
        };
        if (!string.IsNullOrEmpty(resource)) form["resource"] = resource;
        var scopeText = Join(scope);
        if (scopeText is not null) form["scope"] = scopeText;
        using var body = await PostFormAsync(meta.TokenEndpoint, () => form, retryOnReset: false, ct).ConfigureAwait(false);
        return Delegated(body);
    }

    /// <summary>An approval as the platform answers it, read with the agent's own token.</summary>
    public async Task<ApprovalRecord> GetApprovalAsync(string approvalId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(approvalId) || approvalId is "." or "..")
            throw new AuthFIConfigurationException("The approval id is required, and is not a path segment such as \"..\".");
        var template = await ApprovalEndpointAsync(ct).ConfigureAwait(false);
        var url = template.Replace("{id}", Uri.EscapeDataString(approvalId));
        var token = await GetTokenAsync(null, ct).ConfigureAwait(false);
        string text;
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Authorization = new("Bearer", token.Reveal());
            using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            text = await ReadBoundedAsync(res, ct).ConfigureAwait(false);
            if (!res.IsSuccessStatusCode) throw Failure((int)res.StatusCode, text);
        }
        catch (HttpRequestException) { throw new AuthFIException("connection_failed", "The request to the issuer failed.", 502); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new AuthFIException("timeout", "The issuer did not answer in time.", 504); }
        using var doc = Parse(text);
        var data = doc.RootElement.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Object ? d : doc.RootElement;
        var id = Str(data, "approval_id") ?? Str(data, "id") ?? approvalId;
        return new ApprovalRecord(id, Str(data, "status") ?? "", Str(data, "action") ?? "", Str(data, "expires_at"), Str(data, "resolved_at"));
    }

    // ---- wire ----

    private Dictionary<string, string> ClientAuth(string tokenEndpoint) => new()
    {
        ["client_id"] = _agentId,
        ["client_assertion_type"] = JwtBearer,
        ["client_assertion"] = _key.Assertion(_agentId, tokenEndpoint, _time.GetUtcNow()),
    };

    private async Task<Meta> MetaAsync(CancellationToken ct)
    {
        var cached = _meta;
        if (cached is not null && _time.GetUtcNow() - cached.At is { } age && age >= TimeSpan.Zero && age < TimeSpan.FromHours(1)) return cached;
        using var oauth = Parse(await GetTextAsync(_issuer + "/.well-known/oauth-authorization-server", ct).ConfigureAwait(false));
        var root = oauth.RootElement;
        if (Str(root, "issuer")?.TrimEnd('/') != _issuer)
            throw new AuthFIException("metadata_invalid", "The discovery document does not belong to this issuer.", 502);
        var token = Endpoint(Str(root, "token_endpoint")) ?? throw new AuthFIException("metadata_invalid", "The issuer publishes no token endpoint on its own host.", 502);
        var fresh = new Meta(token, Endpoint(Str(root, "backchannel_authentication_endpoint")), _time.GetUtcNow());
        _meta = fresh;
        return fresh;
    }

    /// <summary>The approval endpoint template from the agent configuration. Only a successful answer is remembered.</summary>
    private async Task<string> ApprovalEndpointAsync(CancellationToken ct)
    {
        if (_approvalEndpoint is { } known) return known;
        using var cfg = Parse(await GetTextAsync(_issuer + "/.well-known/agent-configuration", ct).ConfigureAwait(false));
        var named = Str(cfg.RootElement, "issuer");
        if (named is not null && named.TrimEnd('/') != _issuer)
            throw new AuthFIException("metadata_invalid", "The agent configuration does not belong to this issuer.", 502);
        string? approval = null;
        if (cfg.RootElement.TryGetProperty("endpoints", out var eps) && eps.ValueKind == JsonValueKind.Object)
            approval = Endpoint(Str(eps, "approval"));
        if (approval is null) throw new AuthFIException("approval_unavailable", "The issuer publishes no approval endpoint.", 501);
        _approvalEndpoint = approval;
        return approval;
    }

    /// <summary>An endpoint the agent may send credentials to: on the issuer's own scheme, host and port.</summary>
    private string? Endpoint(string? url) => url is not null && OnIssuerOrigin(url.Replace("{id}", "x")) ? url : null;

    private bool OnIssuerOrigin(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) && string.IsNullOrEmpty(u.UserInfo)
        && u.Scheme == _origin.Scheme && u.Port == _origin.Port && string.Equals(u.Host, _origin.Host, StringComparison.OrdinalIgnoreCase);

    private async Task<string> GetTextAsync(string url, CancellationToken ct)
    {
        try
        {
            using var res = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!res.IsSuccessStatusCode)
                throw new AuthFIException("metadata_invalid", $"The issuer answered {(int)res.StatusCode} for its discovery document.", 502);
            return await ReadBoundedAsync(res, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException) { throw new AuthFIException("metadata_invalid", "The issuer's discovery document could not be fetched.", 502); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new AuthFIException("timeout", "The issuer did not answer in time.", 504); }
    }

    private async Task<JsonDocument> PostFormAsync(string url, Func<Dictionary<string, string>> form, bool retryOnReset, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new FormUrlEncodedContent(form()) };
                req.Headers.Accept.ParseAdd("application/json");
                using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                var text = await ReadBoundedAsync(res, ct).ConfigureAwait(false);
                if (!res.IsSuccessStatusCode) throw Failure((int)res.StatusCode, text);
                return Parse(text);
            }
            catch (HttpRequestException e) when (retryOnReset && attempt == 0 && IsReset(e))
            {
                // A connection the server closed while it sat in the pool: the request never arrived. Once.
            }
            catch (HttpRequestException)
            {
                throw new AuthFIException("connection_failed", "The request to the issuer failed.", 502);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new AuthFIException("timeout", "The issuer did not answer in time.", 504);
            }
        }
    }

    // With ResponseHeadersRead the client's own timeout stops at the headers, so the body gets the same budget here.
    private async Task<string> ReadBoundedAsync(HttpResponseMessage res, CancellationToken ct)
    {
        const int limit = 1 << 20;
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(_http.Timeout);
        if (res.Content.Headers.ContentLength > limit) throw new HttpRequestException("answer too large");
        await res.Content.LoadIntoBufferAsync(limit).WaitAsync(budget.Token).ConfigureAwait(false); // a streamed answer fails here as a transport error
        var text = await res.Content.ReadAsStringAsync(budget.Token).ConfigureAwait(false);
        if (text.Length > limit) throw new HttpRequestException("answer too large"); // an already-buffered one is checked here
        return text;
    }

    private static bool IsReset(HttpRequestException e) => e.InnerException is IOException or SocketException;

    private static JsonDocument Parse(string text)
    {
        try { return JsonDocument.Parse(text); }
        catch (JsonException) { throw new AuthFIException("invalid_response", "The issuer answered something that is not JSON.", 502); }
    }

    private static readonly Regex JwtShaped = new(@"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", RegexOptions.Compiled);

    /// <summary>The OAuth error body as an exception. The server's text is shortened and any token-shaped string removed.</summary>
    private static AuthFIException Failure(int status, string body)
    {
        string code = "error", description = "";
        try
        {
            using var doc = JsonDocument.Parse(body);
            code = Str(doc.RootElement, "error") ?? code;
            description = Str(doc.RootElement, "error_description") ?? "";
        }
        catch (JsonException) { /* not JSON: say nothing of the body */ }
        code = Regex.IsMatch(code, @"^[a-z0-9_.:-]{1,64}\z") ? code : "error";
        description = Regex.Replace(JwtShaped.Replace(description, "<token>"), @"[\p{C}\s]+", " ").Trim();
        if (description.Length > 200) description = description[..200];
        var message = $"The issuer refused the request ({status}, {code})" + (description.Length > 0 ? ": " + description : ".");
        return status switch
        {
            401 when code is "invalid_client" or "agent_revoked" or "invalid_token" => new AuthFIAgentRevokedException(message),
            403 => new AuthFIRefusedException(code, message),
            _ => new AuthFIException(code, message, status),
        };
    }

    private static Secret TokenFrom(JsonDocument body, out int expiresIn)
    {
        var token = Str(body.RootElement, "access_token");
        if (string.IsNullOrEmpty(token)) throw new AuthFIException("invalid_response", "The token endpoint answered no access_token.", 502);
        expiresIn = Num(body.RootElement, "expires_in") is > 0 and var e ? e : 0;
        return new Secret(token);
    }

    private DelegatedToken Delegated(JsonDocument body)
    {
        var token = TokenFrom(body, out var expiresIn);
        using var claims = Payload(token.Reveal());
        var person = Strip(Str(claims.RootElement, "sub") ?? "", "user:");
        string agent = "";
        if (claims.RootElement.TryGetProperty("act", out var act) && act.ValueKind == JsonValueKind.Object)
            agent = Strip(Str(act, "sub") ?? "", "agent:");
        if (person.Length == 0 || agent.Length == 0)
            throw new AuthFIException("invalid_response", "The delegated token names no person or no agent.", 502);
        if (agent != _agentId)
            throw new AuthFIException("invalid_response", "The delegated token names another agent.", 502);
        var expires = _time.GetUtcNow().AddSeconds(expiresIn);
        if (claims.RootElement.TryGetProperty("exp", out var exp) && exp.ValueKind == JsonValueKind.Number && exp.TryGetInt64(out var e)
            && e > 0 && e < 253402300799)
            expires = DateTimeOffset.FromUnixTimeSeconds(e);
        var scope = (Str(body.RootElement, "scope") ?? Str(claims.RootElement, "scope") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return new DelegatedToken(token, expires, person, agent, scope);
    }

    private static JsonDocument Payload(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) throw new AuthFIException("invalid_response", "The delegated token is not a JWT.", 502);
        try { return JsonDocument.Parse(B64.Decode(parts[1])); }
        catch (Exception e) when (e is FormatException or JsonException) { throw new AuthFIException("invalid_response", "The delegated token is not a JWT.", 502); }
    }

    private static string Strip(string value, string prefix) => value.StartsWith(prefix, StringComparison.Ordinal) ? value[prefix.Length..] : value;

    private static string? Join(IEnumerable<string>? scope)
    {
        if (scope is null) return null;
        var joined = string.Join(' ', scope.Select(s => s.Trim()).Where(s => s.Length > 0));
        return joined.Length > 0 ? joined : null;
    }

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static int? Num(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i) ? i : null;
}

/// <summary>An approval as the platform answers it.</summary>
public sealed record ApprovalRecord(string ApprovalId, string Status, string Action, string? ExpiresAt, string? ResolvedAt);
