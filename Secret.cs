using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AuthFI;

/// <summary>
/// Holds a token, assertion, private key or client secret. Every way of turning it into text
/// (<c>ToString</c>, string interpolation, JSON, the debugger) gives the redacted form; the value
/// leaves only through <see cref="Reveal"/>, a name that stands out in review.
/// </summary>
[DebuggerDisplay("Secret(****)")]
[JsonConverter(typeof(SecretJsonConverter))]
public sealed class Secret : IFormattable
{
    public const string Redacted = "Secret(****)";

    private readonly string _value;

    public Secret(string value)
    {
        _value = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>The raw value. Call it inside the request that needs it and keep no reference.</summary>
    public string Reveal() => _value;

    public override string ToString() => Redacted;

    public string ToString(string? format, IFormatProvider? formatProvider) => Redacted;

    /// <summary>Constant-time comparison of the two values.</summary>
    public bool ValueEquals(Secret? other)
    {
        if (other is null) return false;
        var a = Encoding.UTF8.GetBytes(_value);
        var b = Encoding.UTF8.GetBytes(other._value);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    // Reference equality only: a value-based Equals would invite a timing-leaking == on secrets.
    public override bool Equals(object? obj) => ReferenceEquals(this, obj);

    public override int GetHashCode() => System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(this);
}

internal sealed class SecretJsonConverter : JsonConverter<Secret>
{
    public override Secret Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        throw new NotSupportedException("A Secret is not read from JSON.");

    public override void Write(Utf8JsonWriter writer, Secret value, JsonSerializerOptions options) =>
        writer.WriteStringValue(Secret.Redacted);
}
