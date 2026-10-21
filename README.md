# AuthFI .NET SDK

Official .NET SDK for [AuthFI](https://authfi.io), the identity control plane.

## Install

The package is not on NuGet yet. Until it is, add the project from source:

```bash
git clone https://github.com/authfi/authfi-dotnet-sdk
dotnet add reference authfi-dotnet-sdk/AuthFI.csproj
```

## Quick start: protect an API

```csharp
// The project's issuer, and the audience of the API this server is: its own client id.
var auth = new AuthFIClient("https://acme.authfi.io", audience: "api_orders");

// ASP.NET Core minimal API
app.MapGet("/api/users", (HttpContext ctx) => {
    var user = auth.Authenticate(ctx);
    auth.RequirePermissions(user, "read:users");
    return Results.Ok(users);
});
```

## What is checked

`VerifyToken`, `VerifyTokenAsync` and `Authenticate` accept an access token only when all of these hold:

- it is a signed JWT (three parts, at most 16 KiB) whose `typ` is `at+jwt`, so an ID token is refused;
- its `alg` is RS256, PS256, ES256 or EdDSA and fits the key the issuer publishes under the token's `kid`.
  Agent, CIBA and delegated tokens are EdDSA; `none` and HMAC algorithms are refused;
- the signature verifies against the keys in the issuer's `jwks_uri`, found through
  `<issuer>/.well-known/oauth-authorization-server`. Keys come from nowhere else; the token's own `jwk`, `jku` and `x5u` are ignored;
- `iss` equals the issuer, `aud` contains the audience you configured, `exp` has not passed, `nbf` and `iat` are not in the future
  (60 seconds of leeway by default), and `sub` and `tenant_id` are present;
- a token bound to a key (`cnf`) or a mission (`authfi_mandate`) and a chain of actors are refused as Bearer tokens.

A refusal throws `AuthFIException` with a stable `Code` (for example `token_expired`, `token_audience_mismatch`) and the HTTP `Status` to answer with.

The audience is required. AuthFI's own audiences, meaning the issuer, any URL on its host and the first-party client ids,
are refused when the verifier is built, because accepting one would let a token minted for the AuthFI gateway be replayed at your API.
Mint tokens for your API with `resource=<your API's client id>`.

Pin the tenant when you know it:

```csharp
var options = new AuthFIVerifierOptions { Issuer = "https://acme.authfi.io", ExpectedTenantId = "4e46e0c4-..." };
options.Audiences.Add("api_orders");
var auth = new AuthFIClient(options);
```

## Secrets

`Secret` holds a token or key. `ToString`, string interpolation, JSON and the debugger all show `Secret(****)`; the value
leaves only through `Reveal()`. A verified `AuthFIClaims` keeps no raw token, and an `AuthFIException` never carries token content.
`Verify` and `VerifyAsync` accept a `Secret` or a string.

## Agents

An AI agent has its own key and gets its own token; no secret is shared with the framework that runs it.

```csharp
using AuthFI.Agents;

// Environment: AUTHFI_ISSUER, AUTHFI_AGENT_ID, AUTHFI_AGENT_KEY (PEM) or AUTHFI_AGENT_KEY_FILE, AUTHFI_AGENT_KEY_ID.
var agent = AgentAuth.FromEnvironment();

// The agent's own access token for an API it has been granted. Cached until a minute before it expires.
Secret token = await agent.GetTokenAsync(resource: "api_orders");

// Per-request credentials for an HttpClient (the gateway, an MCP transport): nothing holds the token.
var http = new HttpClient(new AuthFIBearerHandler(agent));
```

A key file named by `AUTHFI_AGENT_KEY_FILE` must be closed to others (at most read for its owner's group). Keys are Ed25519, P-256 or RSA 2048 to 4096 bits: `AgentKey.Generate("EdDSA")`, `AgentKey.Load(pem)`, `key.PublicJwk()`.

Acting for a person, with their consent on their own device (CIBA), or from a token they hold (RFC 8693):

```csharp
var ask = await agent.BackchannelAuthorizeAsync("ann@example.com", "Refund order 4411");
DelegatedToken delegated = await agent.AwaitUserTokenAsync(ask);          // or poll yourself: agent.PollAsync(ask)
DelegatedToken viaExchange = await agent.ExchangeAsync(personToken, resource: "api_orders");
// delegated.Person, delegated.Agent, delegated.Token (a Secret)
```

Read the gateway's answer to a tool call one way:

```csharp
GatewayAnswer answer = GatewayAnswer.Read(callToolResultJson);
// Allowed, Refused (Code, Reason, RequiredScope) or ApprovalRequired (ApprovalId, kept away from the model).
// answer.ModelText() is what a model may read.
```

A 401 from the gateway throws `AuthFIAgentRevokedException` and a 403 `AuthFIRefusedException`, so an app can tell a revoked agent from a bug.
Tokens, keys and approval handles are `Secret` values and never appear in `ToString`, JSON or exception text.

## Permission and role checks

```csharp
auth.RequirePermissions(user, "read:users");   // all of them
auth.RequireRole(user, "admin");               // any of them
```

## Tests

```bash
dotnet test tests/AuthFI.Tests
```

## License

Apache-2.0
