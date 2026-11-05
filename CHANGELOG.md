# Changelog

All notable changes to this package. It follows [Semantic Versioning](https://semver.org): before 1.0 a minor
version may break, but only with an entry here.

## 0.2.0

The first version published to NuGet. Earlier versions were added from source.

### Added

- **Agents.** `AgentKey` and `AgentAuth` give an AI agent its own key and token (`private_key_jwt`), CIBA,
  RFC 8693 token exchange and approvals. `GatewayAnswer` reads the gateway's answers one way, and a per-request
  bearer handler sends the token with typed 401 and 403 errors. Tokens, keys and approval handles are `Secret`
  values.
- **Strict access-token verification** for RS256, PS256, ES256 and EdDSA tokens, with the key chosen by the `kid`
  the token names. Keys come from the issuer's discovery document.

### Changed

- **Verification is strict.** `typ` must be `at+jwt`, and `iss`, a configured audience that is never AuthFI's own,
  `exp`, `sub` and `tenant_id` are required. **Breaking** for code that relied on the earlier, looser checks.
- `Secret` redacts every text form, so a credential does not reach a log or an exception message.
- Targets .NET 8.
