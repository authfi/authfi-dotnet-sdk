using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace AuthFI.Agents;

/// <summary>
/// An agent's signing key: Ed25519 (EdDSA), P-256 (ES256) or RSA 2048 to 4096 bits (PS256). The private key
/// never leaves this object except through <see cref="ExportPrivatePem"/>, which returns a <see cref="Secret"/>.
/// </summary>
public sealed class AgentKey
{
    private readonly Func<byte[], byte[]> _sign;
    private readonly JsonObject _publicJwk;
    private readonly Secret _pem;

    public string Alg { get; }
    public string Kid { get; }

    private AgentKey(string alg, string kid, Func<byte[], byte[]> sign, JsonObject jwkWithoutKid, Secret pem)
    {
        Alg = alg;
        _sign = sign;
        _pem = pem;
        Kid = string.IsNullOrEmpty(kid) ? Thumbprint(jwkWithoutKid) : kid;
        _publicJwk = jwkWithoutKid;
        _publicJwk["kid"] = Kid;
        _publicJwk["use"] = "sig";
        _publicJwk["alg"] = alg;
    }

    /// <summary>A new key. <paramref name="alg"/> is EdDSA, ES256 or PS256. Without a kid, the RFC 7638 thumbprint is used.</summary>
    public static AgentKey Generate(string alg = "EdDSA", string? kid = null)
    {
        switch (alg)
        {
            case "EdDSA":
            {
                var gen = new Ed25519KeyPairGenerator();
                gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
                var pair = gen.GenerateKeyPair();
                var info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private);
                return FromEd25519((Ed25519PrivateKeyParameters)pair.Private, kid, Pem(info.GetEncoded()));
            }
            case "ES256":
            {
                var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                return FromEc(ec, kid, Pem(ec.ExportPkcs8PrivateKey()));
            }
            case "PS256":
            {
                var rsa = RSA.Create(3072);
                return FromRsa(rsa, kid, Pem(rsa.ExportPkcs8PrivateKey()));
            }
            default:
                throw new AuthFIConfigurationException("alg must be EdDSA, ES256 or PS256.");
        }
    }

    /// <summary>Loads a PKCS#8 ("PRIVATE KEY"), "RSA PRIVATE KEY" or "EC PRIVATE KEY" PEM.</summary>
    public static AgentKey Load(string pem, string? kid = null)
    {
        try
        {
            var fields = PemEncoding.Find(pem.AsSpan());
            var label = pem[fields.Label];
            var der = Convert.FromBase64String(pem[fields.Base64Data]);
            var keep = new Secret(pem);
            switch (label)
            {
                case "RSA PRIVATE KEY":
                {
                    var rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(der, out _);
                    return FromRsa(rsa, kid, keep);
                }
                case "EC PRIVATE KEY":
                {
                    var ec = ECDsa.Create();
                    ec.ImportECPrivateKey(der, out _);
                    return FromEc(ec, kid, keep);
                }
                case "PRIVATE KEY":
                {
                    var key = PrivateKeyFactory.CreateKey(der);
                    if (key is Ed25519PrivateKeyParameters ed) return FromEd25519(ed, kid, keep);
                    if (key is Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)
                    {
                        var rsa = RSA.Create();
                        rsa.ImportPkcs8PrivateKey(der, out _);
                        return FromRsa(rsa, kid, keep);
                    }
                    if (key is ECPrivateKeyParameters)
                    {
                        var ec = ECDsa.Create();
                        ec.ImportPkcs8PrivateKey(der, out _);
                        return FromEc(ec, kid, keep);
                    }
                    break;
                }
            }
        }
        catch (AuthFIConfigurationException) { throw; }
        catch (Exception e) when (e is CryptographicException or FormatException or ArgumentException or InvalidOperationException
                                      or IOException or Org.BouncyCastle.Security.SecurityUtilityException)
        {
            // The message is fixed on purpose: the library's own text can echo key material.
        }
        throw new AuthFIConfigurationException("The key is not a PEM private key of a supported type (Ed25519, P-256 or RSA 2048 to 4096 bits).");
    }

    /// <summary>The public key as a JWK, ready to register: kid, use, alg and the public parameters only.</summary>
    public JsonObject PublicJwk() => (JsonObject)JsonNode.Parse(_publicJwk.ToJsonString())!;

    /// <summary>The private key as PKCS#8 or the original PEM, for storing. Treat it as the key itself.</summary>
    public Secret ExportPrivatePem() => _pem;

    public override string ToString() => $"AgentKey(kid={Kid}, alg={Alg})";

    internal byte[] Sign(byte[] data) => _sign(data);

    /// <summary>An RFC 7523 client assertion for <paramref name="clientId"/>, valid for at most 120 seconds.</summary>
    internal string Assertion(string clientId, string audience, DateTimeOffset now, int lifetimeSeconds = 120)
    {
        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(audience))
            throw new AuthFIConfigurationException("A client assertion needs the client id and the audience.");
        if (lifetimeSeconds <= 0 || lifetimeSeconds > 120)
            throw new AuthFIConfigurationException("An assertion lives at most 120 seconds.");
        var iat = now.ToUnixTimeSeconds();
        var header = new JsonObject { ["alg"] = Alg, ["typ"] = "JWT", ["kid"] = Kid };
        var claims = new JsonObject
        {
            ["iss"] = clientId, ["sub"] = clientId, ["aud"] = audience,
            ["jti"] = Guid.NewGuid().ToString(), ["iat"] = iat, ["exp"] = iat + lifetimeSeconds,
        };
        var input = B64Url(Encoding.UTF8.GetBytes(header.ToJsonString())) + "." + B64Url(Encoding.UTF8.GetBytes(claims.ToJsonString()));
        return input + "." + B64Url(_sign(Encoding.ASCII.GetBytes(input)));
    }

    private static AgentKey FromEd25519(Ed25519PrivateKeyParameters priv, string? kid, Secret pem)
    {
        var pub = priv.GeneratePublicKey();
        var jwk = new JsonObject { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = B64Url(pub.GetEncoded()) };
        return new AgentKey("EdDSA", kid ?? "", data =>
        {
            var s = new Ed25519Signer();
            s.Init(true, priv);
            s.BlockUpdate(data, 0, data.Length);
            return s.GenerateSignature();
        }, jwk, pem);
    }

    private static AgentKey FromEc(ECDsa ec, string? kid, Secret pem)
    {
        var p = ec.ExportParameters(false);
        if (p.Curve.Oid?.FriendlyName is not ("nistP256" or "ECDSA_P256") && p.Curve.Oid?.Value != "1.2.840.10045.3.1.7")
            throw new AuthFIConfigurationException("An EC agent key must be P-256.");
        var jwk = new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = B64Url(p.Q.X!), ["y"] = B64Url(p.Q.Y!) };
        return new AgentKey("ES256", kid ?? "",
            data => ec.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation), jwk, pem);
    }

    private static AgentKey FromRsa(RSA rsa, string? kid, Secret pem)
    {
        if (rsa.KeySize < 2048 || rsa.KeySize > 4096)
            throw new AuthFIConfigurationException("An RSA agent key must be 2048 to 4096 bits.");
        var p = rsa.ExportParameters(false);
        var jwk = new JsonObject { ["kty"] = "RSA", ["n"] = B64Url(p.Modulus!), ["e"] = B64Url(p.Exponent!) };
        return new AgentKey("PS256", kid ?? "",
            data => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss), jwk, pem);
    }

    private static Secret Pem(byte[] pkcs8) => new(new string(PemEncoding.Write("PRIVATE KEY", pkcs8)));

    // RFC 7638: the members of the public key in lexicographic order, no whitespace.
    private static string Thumbprint(JsonObject jwk)
    {
        var sorted = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in new[] { "crv", "e", "kty", "n", "x", "y" })
            if (jwk[name] is JsonNode v) sorted[name] = v.GetValue<string>();
        var json = "{" + string.Join(",", sorted.Select(kv => $"{JsonSerializer.Serialize(kv.Key)}:{JsonSerializer.Serialize(kv.Value)}")) + "}";
        return B64Url(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
    }

    internal static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
