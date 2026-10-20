using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace AuthFI.Tests;

internal sealed class FakeClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => Now;
}

/// <summary>An HttpMessageHandler that answers from a function and counts requests per path.</summary>
internal sealed class StubHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _answer;
    public List<string> Requests { get; } = new();

    public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> answer) => _answer = answer;

    private HttpResponseMessage Answer(HttpRequestMessage r)
    {
        lock (Requests) Requests.Add(r.RequestUri!.AbsolutePath);
        return _answer(r);
    }

    /// <summary>Answers a request directly, for a test handler that wraps this one.</summary>
    public HttpResponseMessage Respond(HttpRequestMessage request) => Answer(request);

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken ct) => Answer(request);

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
        Task.FromResult(Answer(request));
}

/// <summary>A signing key of one algorithm that can mint tokens and publish itself as a JWK.</summary>
internal sealed class TestKey
{
    public string Alg { get; }
    public string Kid { get; }
    private readonly Func<byte[], byte[]> _sign;
    public JsonObject Jwk { get; }

    private TestKey(string alg, string kid, Func<byte[], byte[]> sign, JsonObject jwk)
    {
        Alg = alg; Kid = kid; _sign = sign; Jwk = jwk;
    }

    public static TestKey Create(string alg, string kid, bool declareAlg = true)
    {
        JsonObject jwk;
        Func<byte[], byte[]> sign;
        switch (alg)
        {
            case "RS256":
            case "PS256":
            {
                var rsa = RSA.Create(2048);
                var p = rsa.ExportParameters(false);
                jwk = new JsonObject { ["kty"] = "RSA", ["n"] = B64u(p.Modulus!), ["e"] = B64u(p.Exponent!) };
                var pad = alg == "PS256" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                sign = d => rsa.SignData(d, HashAlgorithmName.SHA256, pad);
                break;
            }
            case "ES256":
            {
                var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var p = ec.ExportParameters(false);
                jwk = new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = B64u(p.Q.X!), ["y"] = B64u(p.Q.Y!) };
                sign = d => ec.SignData(d, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                break;
            }
            case "EdDSA":
            {
                var gen = new Ed25519KeyPairGenerator();
                gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
                var pair = gen.GenerateKeyPair();
                var priv = (Ed25519PrivateKeyParameters)pair.Private;
                var pub = (Ed25519PublicKeyParameters)pair.Public;
                jwk = new JsonObject { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = B64u(pub.GetEncoded()) };
                sign = d =>
                {
                    var s = new Ed25519Signer();
                    s.Init(true, priv);
                    s.BlockUpdate(d, 0, d.Length);
                    return s.GenerateSignature();
                };
                break;
            }
            default: throw new ArgumentException(alg);
        }
        jwk["kid"] = kid;
        jwk["use"] = "sig";
        if (declareAlg) jwk["alg"] = alg;
        return new TestKey(alg, kid, sign, jwk);
    }

    public string Mint(JsonObject? header = null, JsonObject? payload = null, Action<JsonObject>? editHeader = null,
        Action<JsonObject>? editPayload = null)
    {
        var h = header ?? new JsonObject { ["alg"] = Alg, ["typ"] = "at+jwt", ["kid"] = Kid };
        var p = payload ?? Claims.Default();
        editHeader?.Invoke(h);
        editPayload?.Invoke(p);
        var input = B64u(Encoding.UTF8.GetBytes(h.ToJsonString())) + "." + B64u(Encoding.UTF8.GetBytes(p.ToJsonString()));
        return input + "." + B64u(_sign(Encoding.ASCII.GetBytes(input)));
    }

    /// <summary>Signs header and payload JSON exactly as given, for inputs a JsonObject cannot express (duplicate names, bad escapes).</summary>
    public string MintRaw(string headerJson, string payloadJson)
    {
        var input = B64u(Encoding.UTF8.GetBytes(headerJson)) + "." + B64u(Encoding.UTF8.GetBytes(payloadJson));
        return input + "." + B64u(_sign(Encoding.ASCII.GetBytes(input)));
    }

    public static string B64u(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

internal static class Claims
{
    public const string Issuer = "https://acme.authfi.io";
    public const string Audience = "api_orders";
    public const string Tenant = "4e46e0c4-ec26-48e1-b5bb-04a1ec3ff358";
    public static readonly long Now = new DateTimeOffset(2026, 10, 20, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

    public static JsonObject Default() => new()
    {
        ["iss"] = Issuer,
        ["sub"] = "user:alice@example.com",
        ["aud"] = Audience,
        ["exp"] = Now + 600,
        ["iat"] = Now - 5,
        ["tenant_id"] = Tenant,
        ["email"] = "alice@example.com",
        ["roles"] = new JsonArray("admin"),
        ["permissions"] = new JsonArray("read:users"),
    };
}

/// <summary>An issuer served from memory: discovery plus a key set, with request counting.</summary>
internal sealed class TestIssuer
{
    public List<TestKey> Keys { get; } = new();
    public StubHandler Handler { get; }
    public FakeClock Clock { get; } = new();
    public string MetadataIssuer = Claims.Issuer;
    public int JwksStatus = 200;

    public TestIssuer(params TestKey[] keys)
    {
        Keys.AddRange(keys);
        Handler = new StubHandler(r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            if (path == "/.well-known/oauth-authorization-server")
                return Json(new JsonObject { ["issuer"] = MetadataIssuer, ["jwks_uri"] = Claims.Issuer + "/.well-known/jwks.json" });
            if (path == "/.well-known/jwks.json")
            {
                if (JwksStatus != 200) return new HttpResponseMessage((System.Net.HttpStatusCode)JwksStatus);
                var arr = new JsonArray();
                foreach (var k in Keys) arr.Add(JsonNode.Parse(k.Jwk.ToJsonString()));
                return Json(new JsonObject { ["keys"] = arr });
            }
            return new HttpResponseMessage(System.Net.HttpStatusCode.NotFound);
        });
    }

    private static HttpResponseMessage Json(JsonObject o) =>
        new(System.Net.HttpStatusCode.OK) { Content = new StringContent(o.ToJsonString(), Encoding.UTF8, "application/json") };

    public AuthFIVerifier Verifier(Action<AuthFIVerifierOptions>? edit = null)
    {
        var o = new AuthFIVerifierOptions
        {
            Issuer = Claims.Issuer,
            HttpClient = new HttpClient(Handler),
            TimeProvider = Clock,
            UnknownKidRefetchInterval = TimeSpan.Zero,
        };
        o.Audiences.Add(Claims.Audience);
        edit?.Invoke(o);
        return new AuthFIVerifier(o);
    }
}
