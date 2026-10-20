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
