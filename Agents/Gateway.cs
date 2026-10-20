using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace AuthFI.Agents;

public enum GatewayAnswerKind
{
    /// <summary>The gateway allowed the call; the result is the tool's own answer (which may itself be the tool's error).</summary>
    Allowed,
    /// <summary>The gateway refused the call.</summary>
    Refused,
    /// <summary>A person must approve the call first.</summary>
    ApprovalRequired,
}

/// <summary>
/// What the AuthFI gateway did with one <c>tools/call</c>, read one way. Only an error result can be a refusal or a
/// hold, so a tool whose output quotes the gateway's words is still the tool's answer.
/// </summary>
public sealed class GatewayAnswer
{
    /// <summary>The argument a held call is sent again with, naming the approval a person gave.</summary>
    public const string ApprovalArgument = "_authfi_approval_id";
    /// <summary>What a model is told about a held call: the wait, never an instruction or an id.</summary>
    public const string HoldMessage = "This action is waiting for a person's approval.";
    private const string RefusalMeta = "io.authfi/refusal";

    // The approval id is a path segment later on, so it has the shape of an id and never a dot segment.
    private static readonly Regex Hold = new(
        @"^Waiting for approval ([A-Za-z0-9][A-Za-z0-9_:-]{0,127}) \(([a-z_]{1,64})\)\. A person must approve this action", RegexOptions.Compiled);
    private static readonly Regex IdShape = new(@"^[A-Za-z0-9][A-Za-z0-9_:-]{0,127}\z", RegexOptions.Compiled);

    public GatewayAnswerKind Kind { get; private init; }
    public string? Code { get; private init; }
    public string? Error { get; private init; }
    public string? Reason { get; private init; }
    public string? RequiredScope { get; private init; }
    /// <summary>The approval a person must give. Keep it out of anything a model reads.</summary>
    public string? ApprovalId { get; private init; }

    private GatewayAnswer() { }

    /// <summary>What a model may read about this answer when a framework needs text; it never carries an approval id.</summary>
    public string ModelText(string toolText = "") => Kind switch
    {
        GatewayAnswerKind.ApprovalRequired => HoldMessage,
        GatewayAnswerKind.Refused => RefusedText(),
        _ => toolText,
    };

    // Free text from a refusal is data a tool may have chosen: one short line, no control characters.
    private string RefusedText()
    {
        var code = Plain(Code ?? Error, 64, "[a-z0-9_.:-]+") ?? "refused";
        var reason = Plain(Reason, 160, null);
        var scope = Plain(RequiredScope, 100, "[A-Za-z0-9_.:/*@-]+");
        var text = $"Refused by AuthFI ({code})" + (reason is null ? "" : ": " + reason) + ".";
        return scope is null ? text : text + $" The call needs the scope {scope}.";
    }

    private static string? Plain(string? value, int max, string? allowed)
    {
        if (value is null) return null;
        var line = Regex.Replace(value, @"[\p{C}\s]+", " ").Trim();
        if (line.Length > max) line = line[..max];
        if (line.Length == 0) return null;
        return allowed is null || Regex.IsMatch(line, "^(" + allowed + ")\\z") ? line : null;
    }

    /// <summary>Reads an MCP <c>CallToolResult</c> in its JSON form (<c>isError</c>, <c>content</c>, <c>_meta</c>).</summary>
    public static GatewayAnswer Read(JsonElement callToolResult)
    {
        if (callToolResult.ValueKind != JsonValueKind.Object) return Allowed;
        var isError = callToolResult.TryGetProperty("isError", out var e) && e.ValueKind == JsonValueKind.True;
        var text = new StringBuilder();
        if (callToolResult.TryGetProperty("content", out var content) && content.ValueKind == JsonValueKind.Array)
            foreach (var block in content.EnumerateArray())
                if (block.ValueKind == JsonValueKind.Object && block.TryGetProperty("text", out var t) && t.ValueKind == JsonValueKind.String)
                    text.AppendLine(t.GetString());
        JsonElement? meta = callToolResult.TryGetProperty("_meta", out var m) ? m : null;
        return Read(isError, text.ToString(), meta);
    }

    /// <summary>Reads a result given as its parts, for callers that hold an SDK object rather than JSON.</summary>
    public static GatewayAnswer Read(bool isError, string text, JsonElement? meta = null)
    {
        if (!isError) return Allowed;
        if (meta is { ValueKind: JsonValueKind.Object } mo && mo.TryGetProperty(RefusalMeta, out var r) && r.ValueKind == JsonValueKind.Object)
            return new GatewayAnswer
            {
                Kind = GatewayAnswerKind.Refused,
                Code = Str(r, "code"), Error = Str(r, "error"), Reason = Str(r, "reason"),
                RequiredScope = Str(r, "required_scope"), ApprovalId = Id(Str(r, "approval_id")),
            };
        var hold = Hold.Match((text ?? "").Trim());
        if (hold.Success)
        {
            // Only approval_required and approval_pending wait for a person; approval_denied and the rest are refusals.
            return hold.Groups[2].Value is "approval_required" or "approval_pending"
                ? new GatewayAnswer { Kind = GatewayAnswerKind.ApprovalRequired, ApprovalId = hold.Groups[1].Value, Code = hold.Groups[2].Value }
                : new GatewayAnswer { Kind = GatewayAnswerKind.Refused, Code = hold.Groups[2].Value, ApprovalId = hold.Groups[1].Value };
        }
        return Allowed;
    }

    private static string? Id(string? value) => value is not null && IdShape.IsMatch(value) ? value : null;

    private static GatewayAnswer Allowed => new() { Kind = GatewayAnswerKind.Allowed };

    private static string? Str(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : null;

    /// <summary>The arguments plus the approval a person gave, to send a held call again.</summary>
    public static JsonObject WithApproval(JsonObject? arguments, string approvalId)
    {
        var copy = arguments is null ? new JsonObject() : (JsonObject)JsonNode.Parse(arguments.ToJsonString())!;
        copy[ApprovalArgument] = approvalId;
        return copy;
    }

    /// <summary>
    /// The arguments without an approval id, and whether one was there. Only the adapter adds the id, on its own resume;
    /// one a model wrote is removed, so a model that read a hold message elsewhere cannot spend a person's approval.
    /// </summary>
    public static (JsonObject Arguments, bool Stripped) WithoutApproval(JsonObject? arguments)
    {
        var copy = arguments is null ? new JsonObject() : (JsonObject)JsonNode.Parse(arguments.ToJsonString())!;
        var had = copy.Remove(ApprovalArgument);
        return (copy, had);
    }

    /// <summary>A digest of the tool name and arguments (key order does not matter, the approval argument is ignored), to tie an approval to one call.</summary>
    public static string Digest(string toolName, JsonObject? arguments)
    {
        var (args, _) = WithoutApproval(arguments);
        var sb = new StringBuilder();
        sb.Append(JsonSerializer.Serialize(toolName)).Append('|');
        Canonical(args, sb);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()))).ToLowerInvariant();
    }

    private static void Canonical(JsonNode? node, StringBuilder sb)
    {
        switch (node)
        {
            case JsonObject o:
                sb.Append('{');
                var first = true;
                foreach (var kv in o.OrderBy(k => k.Key, StringComparer.Ordinal))
                {
                    if (!first) sb.Append(',');
                    first = false;
                    sb.Append(JsonSerializer.Serialize(kv.Key)).Append(':');
                    Canonical(kv.Value, sb);
                }
                sb.Append('}');
                break;
            case JsonArray a:
                sb.Append('[');
                for (var i = 0; i < a.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    Canonical(a[i], sb);
                }
                sb.Append(']');
                break;
            case null:
                sb.Append("null");
                break;
            default:
                sb.Append(node.ToJsonString());
                break;
        }
    }

    public override string ToString() => $"GatewayAnswer({Kind}, code={Code})";
}

/// <summary>
/// Adds the agent's current token to each request, so the credential is read per request and never held in a client
/// configuration or header collection. A 401 from the gateway becomes <see cref="AuthFIAgentRevokedException"/> and a 403
/// <see cref="AuthFIRefusedException"/>, so an app can tell a revoked agent from a bug.
/// </summary>
public sealed class AuthFIBearerHandler : DelegatingHandler
{
    private readonly AgentAuth _auth;
    private readonly string? _resource;

    public AuthFIBearerHandler(AgentAuth auth, string? resource = null, HttpMessageHandler? inner = null)
        : base(inner ?? new SocketsHttpHandler { AllowAutoRedirect = false, PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30), PooledConnectionLifetime = TimeSpan.FromMinutes(2) })
    {
        _auth = auth ?? throw new ArgumentNullException(nameof(auth));
        _resource = resource;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var token = await _auth.GetTokenAsync(_resource, ct).ConfigureAwait(false);
        request.Headers.Authorization = new("Bearer", token.Reveal());
        var activity = Activity.Current;
        activity?.SetTag("authfi.agent.id", _auth.AgentId);
        if (!request.Headers.Contains("X-Request-Id"))
            request.Headers.TryAddWithoutValidation("X-Request-Id",
                activity is null ? Guid.NewGuid().ToString("N") : $"{activity.TraceId}-{activity.SpanId}");

        var response = await base.SendAsync(request, ct).ConfigureAwait(false);
        switch ((int)response.StatusCode)
        {
            case 401:
                response.Dispose();
                await _auth.ForgetTokenAsync(_resource, CancellationToken.None).ConfigureAwait(false); // the next request mints afresh
                throw new AuthFIAgentRevokedException("The gateway no longer accepts this agent's credential (401): the agent was revoked or its key retired.");
            case 403:
                response.Dispose();
                throw new AuthFIRefusedException("forbidden", "The gateway refused this agent the call (403).");
        }
        return response;
    }
}
