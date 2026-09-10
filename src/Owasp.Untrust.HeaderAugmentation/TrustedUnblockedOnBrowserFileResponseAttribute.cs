namespace Owasp.Untrust.HeaderAugmentation;

/// <summary>
/// Marks a browser-served file endpoint as reviewed and trusted enough to be exempt
/// from this library's default restrictive browser-file headers.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class TrustedUnblockedOnBrowserFileResponseAttribute : Attribute
{
    /// <summary>
    /// Initializes the explicit, reviewed exemption.
    /// </summary>
    /// <param name="justification">Why allowing the file to run without the restrictive policy is safe.</param>
    /// <exception cref="ArgumentException">Thrown when the justification is blank.</exception>
    public TrustedUnblockedOnBrowserFileResponseAttribute(string justification)
    {
        if (string.IsNullOrWhiteSpace(justification))
        {
            throw new ArgumentException("A non-blank justification is required.", nameof(justification));
        }

        Justification = justification;
    }

    /// <summary>
    /// Gets the review justification for the exceptional trusted response.
    /// </summary>
    public string Justification { get; }
}
