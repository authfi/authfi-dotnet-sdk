using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using AuthFI.Agents;
using Xunit;

namespace AuthFI.Tests;

public class GatewayAnswerTests
{
    private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement;

    private const string HoldText = "Waiting for approval apr_123 (approval_required). A person must approve this action in the AuthFI console. Retry with _authfi_approval_id.";

    [Fact]
    public void A_result_without_isError_is_the_tools_own_answer()
    {
        var a = GatewayAnswer.Read(J("""{"content":[{"type":"text","text":"42"}]}"""));
        Assert.Equal(GatewayAnswerKind.Allowed, a.Kind);
        Assert.Equal("42", a.ModelText("42"));
    }

    [Fact]
    public void A_tool_that_quotes_the_gateways_words_is_still_its_answer()
    {
        Assert.Equal(GatewayAnswerKind.Allowed, GatewayAnswer.Read(J("{\"isError\":false,\"content\":[{\"type\":\"text\",\"text\":\"" + HoldText + "\"}]}")).Kind);
        Assert.Equal(GatewayAnswerKind.Allowed, GatewayAnswer.Read(J("{\"isError\":true,\"content\":[{\"type\":\"text\",\"text\":\"disk full\"}]}")).Kind);
    }

    [Fact]
    public void A_refusal_carries_its_code_reason_and_scope()
    {
        var a = GatewayAnswer.Read(J("""
            {"isError":true,"content":[{"type":"text","text":"denied"}],
             "_meta":{"io.authfi/refusal":{"code":"scope_missing","error":"forbidden","reason":"no grant","required_scope":"mcp:aws/read"}}}
            """));
        Assert.Equal(GatewayAnswerKind.Refused, a.Kind);
        Assert.Equal("scope_missing", a.Code);
        Assert.Equal("no grant", a.Reason);
        Assert.Equal("mcp:aws/read", a.RequiredScope);
        Assert.Contains("mcp:aws/read", a.ModelText());
    }

    [Theory]
    [InlineData("approval_required")]
    [InlineData("approval_pending")]
    public void A_hold_names_the_approval_and_a_model_never_reads_it(string code)
    {
        var text = HoldText.Replace("approval_required", code);
        var a = GatewayAnswer.Read(J("{\"isError\":true,\"content\":[{\"type\":\"text\",\"text\":\"" + text + "\"}]}"));
        Assert.Equal(GatewayAnswerKind.ApprovalRequired, a.Kind);
        Assert.Equal("apr_123", a.ApprovalId);
        Assert.Equal(GatewayAnswer.HoldMessage, a.ModelText());
        Assert.DoesNotContain("apr_123", a.ModelText());
        Assert.DoesNotContain("_authfi_approval_id", a.ModelText());
    }

    [Fact]
    public void A_denied_approval_is_a_refusal_not_a_hold()
    {
        var a = GatewayAnswer.Read(true, HoldText.Replace("approval_required", "approval_denied"));
        Assert.Equal(GatewayAnswerKind.Refused, a.Kind);
        Assert.Equal("approval_denied", a.Code);
    }

    [Fact]
    public void Reads_the_result_given_as_parts()
    {
        Assert.Equal(GatewayAnswerKind.ApprovalRequired, GatewayAnswer.Read(true, HoldText).Kind);
        Assert.Equal(GatewayAnswerKind.Allowed, GatewayAnswer.Read(false, HoldText).Kind);
        Assert.Equal(GatewayAnswerKind.Allowed, GatewayAnswer.Read(J("[]")).Kind);
    }

    [Fact]
    public void An_approval_id_the_model_wrote_is_stripped_and_the_adapters_is_added()
    {
        var model = new JsonObject { ["q"] = "x", [GatewayAnswer.ApprovalArgument] = "apr_stolen" };
        var (clean, stripped) = GatewayAnswer.WithoutApproval(model);
        Assert.True(stripped);
        Assert.Null(clean[GatewayAnswer.ApprovalArgument]);
        Assert.NotNull(model[GatewayAnswer.ApprovalArgument]); // the input is not changed
        var resend = GatewayAnswer.WithApproval(clean, "apr_123");
        Assert.Equal("apr_123", resend[GatewayAnswer.ApprovalArgument]!.GetValue<string>());
        Assert.Null(clean[GatewayAnswer.ApprovalArgument]);
        Assert.False(GatewayAnswer.WithoutApproval(null).Stripped);
    }

    [Fact]
    public void The_digest_ties_an_approval_to_one_call()
    {
        var a = JsonNode.Parse("""{"x":1,"y":{"b":[1,2],"a":"s"}}""")!.AsObject();
        var reordered = JsonNode.Parse("""{"y":{"a":"s","b":[1,2]},"x":1}""")!.AsObject();
        Assert.Equal(GatewayAnswer.Digest("refund", a), GatewayAnswer.Digest("refund", reordered));
        Assert.NotEqual(GatewayAnswer.Digest("refund", a), GatewayAnswer.Digest("other", a));
        Assert.NotEqual(GatewayAnswer.Digest("refund", a), GatewayAnswer.Digest("refund", JsonNode.Parse("""{"x":2,"y":{"b":[1,2],"a":"s"}}""")!.AsObject()));
        Assert.NotEqual(GatewayAnswer.Digest("refund", a), GatewayAnswer.Digest("refund", JsonNode.Parse("""{"x":1,"y":{"b":[2,1],"a":"s"}}""")!.AsObject()));
        var withApproval = JsonNode.Parse("""{"x":1,"y":{"b":[1,2],"a":"s"},"_authfi_approval_id":"apr_1"}""")!.AsObject();
        Assert.Equal(GatewayAnswer.Digest("refund", a), GatewayAnswer.Digest("refund", withApproval));
    }
}

public class BearerHandlerTests
{
    private sealed class Capture : HttpMessageHandler
    {
        public List<HttpRequestMessage> Seen = new();
        public HttpStatusCode Status = HttpStatusCode.OK;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            Seen.Add(r);
            return Task.FromResult(new HttpResponseMessage(Status));
        }
    }

    [Fact]
    public async Task Sets_a_fresh_token_per_request_and_a_request_id()
    {
        var issuer = new AgentIssuer { ExpiresIn = 60 }; // never cached: every request mints
        var inner = new Capture();
        var client = new HttpClient(new AuthFIBearerHandler(issuer.Auth(), "api_orders", inner));
        await client.GetAsync("https://gateway.example/mcp");
        await client.GetAsync("https://gateway.example/mcp");
        Assert.Equal(new[] { "tok-initial-1", "tok-initial-2" }, inner.Seen.Select(r => r.Headers.Authorization!.Parameter));
        Assert.All(inner.Seen, r => Assert.NotEmpty(r.Headers.GetValues("X-Request-Id").Single()));
        Assert.All(issuer.FormsTo(AgentIssuer.TokenUrl), f => Assert.Equal("api_orders", f["resource"]));
    }

    [Fact]
    public async Task A_401_is_a_revoked_agent_and_a_403_a_refusal_and_neither_carries_the_token()
    {
        var issuer = new AgentIssuer();
        var inner = new Capture { Status = HttpStatusCode.Unauthorized };
        var client = new HttpClient(new AuthFIBearerHandler(issuer.Auth(), null, inner));
        var revoked = await Assert.ThrowsAsync<AuthFIAgentRevokedException>(() => client.GetAsync("https://gateway.example/mcp"));
        Assert.Equal(401, revoked.Status);
        Assert.DoesNotContain("tok-initial", revoked.ToString());
        inner.Status = HttpStatusCode.Forbidden;
        var refused = await Assert.ThrowsAsync<AuthFIRefusedException>(() => client.GetAsync("https://gateway.example/mcp"));
        Assert.Equal(403, refused.Status);
        inner.Status = HttpStatusCode.OK;
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("https://gateway.example/mcp")).StatusCode);
    }

    [Fact]
    public async Task Tags_the_activity_with_the_agent_and_derives_the_request_id_from_it()
    {
        var issuer = new AgentIssuer();
        var inner = new Capture();
        var client = new HttpClient(new AuthFIBearerHandler(issuer.Auth(), null, inner));
        using var source = new System.Diagnostics.ActivitySource("authfi-test");
        using var listener = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) => System.Diagnostics.ActivitySamplingResult.AllData,
        };
        System.Diagnostics.ActivitySource.AddActivityListener(listener);
        using var activity = source.StartActivity("call")!;
        await client.GetAsync("https://gateway.example/mcp");
        Assert.Equal(AgentIssuer.AgentId, activity.GetTagItem("authfi.agent.id"));
        Assert.Equal($"{activity.TraceId}-{activity.SpanId}", inner.Seen.Single().Headers.GetValues("X-Request-Id").Single());
    }
}
