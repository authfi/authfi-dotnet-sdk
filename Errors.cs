namespace AuthFI;

/// <summary>
/// A refusal or failure from the SDK. <see cref="Code"/> is the stable machine-readable reason
/// (for example <c>token_expired</c>); <see cref="Status"/> is the HTTP status to answer with.
/// Messages never carry token content, keys or claim values that a caller supplied.
/// </summary>
public class AuthFIException : Exception
{
    public int Status { get; }
    public string Code { get; }

    public AuthFIException(string message, int status) : this("error", message, status) { }

    public AuthFIException(string code, string message, int status) : base(message)
    {
        Code = code;
        Status = status;
    }

    public override string ToString() => $"{nameof(AuthFIException)}({Code}, {Status}): {Message}";
}

/// <summary>The SDK was configured in a way that can never verify safely. Thrown at construction.</summary>
public sealed class AuthFIConfigurationException : ArgumentException
{
    public AuthFIConfigurationException(string message) : base(message) { }
}
