using Microsoft.AspNetCore.Http;

namespace Owasp.Untrust.HeaderAugmentation;

/// <summary>
/// Defines the headers applied to untrusted browser-file responses.
/// </summary>
public static class HeaderAugmentationDefaults
{
    /// <summary>
    /// Gets the restrictive content security policy applied to file responses.
    /// </summary>
    public const string ContentSecurityPolicy = "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'";

    internal static void Apply(HttpResponse response)
    {
        response.Headers.TryAdd("Content-Security-Policy", ContentSecurityPolicy);
        response.Headers.TryAdd("X-Content-Type-Options", "nosniff");
    }
}
