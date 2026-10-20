using System.Collections;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace AuthFI.Tests;

/// <summary>Proves that no token, key or secret can leave through ToString, JSON, logs, exceptions or object graphs.</summary>
public class SecretHygieneTests
{
    private const string Marker = "s3cr3t-m4rker-value";

    [Fact]
    public void A_Secret_prints_redacted_in_every_text_form()
    {
        var s = new Secret(Marker);
        Assert.DoesNotContain(Marker, s.ToString());
        Assert.DoesNotContain(Marker, $"{s}");
        Assert.DoesNotContain(Marker, string.Format("{0}", s));
        Assert.DoesNotContain(Marker, string.Format("{0:X}", s));
        Assert.DoesNotContain(Marker, s.ToString("G", null));
        Assert.DoesNotContain(Marker, JsonSerializer.Serialize(s));
        Assert.DoesNotContain(Marker, JsonSerializer.Serialize(new { token = s }));
        Assert.DoesNotContain(Marker, JsonSerializer.Serialize<object>(s));
        Assert.DoesNotContain(Marker, new[] { s }.ToString()!);
        var attr = typeof(Secret).GetCustomAttribute<System.Diagnostics.DebuggerDisplayAttribute>();
        Assert.NotNull(attr);
        Assert.DoesNotContain("_value", attr!.Value);
        Assert.Equal(Marker, s.Reveal());
    }

    [Fact]
    public void A_Secret_compares_by_value_only_through_the_constant_time_method()
    {
        Assert.True(new Secret("a").ValueEquals(new Secret("a")));
        Assert.False(new Secret("a").ValueEquals(new Secret("b")));
        Assert.False(new Secret("a").ValueEquals(null));
        Assert.False(new Secret("a").Equals(new Secret("a")));
    }

    [Fact]
    public void A_Secret_cannot_be_read_back_from_JSON()
    {
        Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<Secret>("\"x\""));
    }

    public static IEnumerable<object[]> BadTokens()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var other = TestKey.Create("EdDSA", "k1");
        var rsa = TestKey.Create("RS256", "k1");
        yield return new object[] { "wrong-signer", other.Mint(editPayload: p => p["email"] = Marker) };
        yield return new object[] { "id-token", key.Mint(editHeader: h => h["typ"] = "JWT", editPayload: p => p["email"] = Marker) };
        yield return new object[] { "expired", key.Mint(editPayload: p => { p["exp"] = Claims.Now - 9999; p["email"] = Marker; }) };
        yield return new object[] { "audience", key.Mint(editPayload: p => { p["aud"] = Marker; }) };
        yield return new object[] { "issuer", key.Mint(editPayload: p => { p["iss"] = "https://" + Marker + ".example"; }) };
        yield return new object[] { "alg", key.Mint(editHeader: h => h["alg"] = Marker) };
        yield return new object[] { "kid", key.Mint(editHeader: h => h["kid"] = Marker) };
        yield return new object[] { "crit", key.Mint(editHeader: h => h["crit"] = new JsonArray(Marker)) };
        yield return new object[] { "claim-type", key.Mint(editPayload: p => p["sub"] = new JsonArray(Marker)) };
        yield return new object[] { "rsa-vs-ed", rsa.Mint(editPayload: p => p["email"] = Marker) };
        yield return new object[] { "garbage", Marker + "." + Marker + "." + Marker };
        yield return new object[] { "not-base64-json", Convert.ToBase64String(Encoding.UTF8.GetBytes(Marker)) + ".e30.AA" };
    }

    [Theory, MemberData(nameof(BadTokens))]
    public void A_refused_token_leaves_no_trace_of_itself_in_the_exception(string why, string token)
    {
        var good = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(good).Verifier();
        var e = Assert.Throws<AuthFIException>(() => v.Verify(token));
        AssertClean(e, token, why);
    }

    [Theory, MemberData(nameof(BadTokens))]
    public async Task The_async_path_is_as_clean(string why, string token)
    {
        var good = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(good).Verifier();
        var e = await Assert.ThrowsAsync<AuthFIException>(() => v.VerifyAsync(token));
        AssertClean(e, token, why);
    }

    private static void AssertClean(Exception e, string token, string why)
    {
        var all = new StringBuilder();
        for (Exception? x = e; x is not null; x = x.InnerException)
        {
            all.Append(x.Message).Append(x.ToString()).Append(x.Source).Append(x.StackTrace);
            foreach (DictionaryEntry d in x.Data) all.Append(d.Key).Append(d.Value);
        }
        var text = all.ToString();
        Assert.True(!text.Contains(Marker), $"{why}: the exception text carries the marker");
        Assert.True(!text.Contains(token), $"{why}: the exception text carries the token");
        foreach (var part in token.Split('.').Where(p => p.Length > 8))
            Assert.True(!text.Contains(part), $"{why}: the exception text carries a segment of the token");
        Assert.Null(e.InnerException);
    }

    [Fact]
    public void A_failed_key_fetch_names_no_url_with_a_credential_and_no_token()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key) { JwksStatus = 500 };
        var token = key.Mint(editPayload: p => p["email"] = Marker);
        var e = Assert.Throws<AuthFIException>(() => issuer.Verifier().Verify(token));
        Assert.DoesNotContain(Marker, e.ToString());
        Assert.DoesNotContain(token, e.ToString());
        Assert.Null(e.InnerException);
    }

    [Fact]
    public void Verifying_writes_nothing_to_the_console()
    {
        var good = TestKey.Create("EdDSA", "k1");
        var v = new TestIssuer(good).Verifier();
        var oldOut = Console.Out; var oldErr = Console.Error;
        var o = new StringWriter(); var er = new StringWriter();
        Console.SetOut(o); Console.SetError(er);
        try
        {
            v.Verify(good.Mint());
            foreach (var row in BadTokens())
                try { v.Verify((string)row[1]); } catch (AuthFIException) { }
        }
        finally { Console.SetOut(oldOut); Console.SetError(oldErr); }
        Assert.Equal("", o.ToString());
        Assert.Equal("", er.ToString());
    }

    [Fact]
    public void Nothing_that_survives_a_verification_holds_the_raw_token()
    {
        var key = TestKey.Create("RS256", "k1");
        var issuer = new TestIssuer(key);
        var token = key.Mint(editPayload: p => p["jti"] = "jti-" + Marker);
        var client = new AuthFIClient(new AuthFIVerifierOptions
        {
            Issuer = Claims.Issuer, HttpClient = new HttpClient(issuer.Handler), TimeProvider = issuer.Clock,
            Audiences = { "api_orders" },
        });
        var claims = client.VerifyToken(token);
        foreach (var part in token.Split('.'))
        {
            Assert.False(GraphContains(client, part), "the client holds a token segment");
            Assert.False(GraphContains(claims, part), "the claims hold a token segment");
        }
        Assert.DoesNotContain(token, client.ToString());
        Assert.DoesNotContain(token, client.Verifier.ToString());
        Assert.DoesNotContain(token, claims.ToString());
        Assert.DoesNotContain(token, JsonSerializer.Serialize(claims));
    }

    [Fact]
    public void A_Secret_handed_to_Verify_is_not_kept()
    {
        var key = TestKey.Create("EdDSA", "k1");
        var issuer = new TestIssuer(key);
        var v = issuer.Verifier();
        var token = key.Mint();
        v.Verify(new Secret(token));
        foreach (var part in token.Split('.'))
            Assert.False(GraphContains(v, part));
    }

    /// <summary>Walks every field reachable from the root and reports whether a string contains the needle.</summary>
    private static bool GraphContains(object root, string needle)
    {
        var seen = new HashSet<object>(ReferenceEqualityComparer.Instance);
        var queue = new Queue<object>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            var o = queue.Dequeue();
            if (!seen.Add(o)) continue;
            switch (o)
            {
                case string s: if (s.Contains(needle)) return true; continue;
                case byte[] b: if (Encoding.UTF8.GetString(b).Contains(needle)) return true; continue;
                case Type or Delegate or System.Reflection.Assembly or System.Reflection.Module: continue;
                case HttpClient or HttpMessageHandler: continue;
            }
            var t = o.GetType();
            if (t.IsPrimitive || t.IsEnum || t.Namespace?.StartsWith("System.Security") == true) continue;
            if (o is IEnumerable en)
                foreach (var item in en) if (item is not null) queue.Enqueue(item);
            for (var ty = t; ty is not null && ty != typeof(object); ty = ty.BaseType)
                foreach (var f in ty.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                {
                    if (f.FieldType.IsPrimitive || f.FieldType.IsPointer) continue;
                    object? val;
                    try { val = f.GetValue(o); } catch { continue; }
                    if (val is not null) queue.Enqueue(val);
                }
        }
        return false;
    }
}
