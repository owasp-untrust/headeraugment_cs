using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;

namespace Owasp.Untrust.HeaderAugmentation;

/// <summary>
/// Provides minimal-API endpoint registration for restrictive browser-file headers.
/// </summary>
public static class HeaderAugmentationRouteHandlerBuilderExtensions
{
    /// <summary>
    /// Adds restrictive headers to an <see cref="IFileHttpResult"/> returned by this endpoint,
    /// unless the endpoint is explicitly marked as trusted.
    /// </summary>
    /// <param name="builder">The route handler builder for a minimal-API endpoint.</param>
    /// <returns>The same route handler builder.</returns>
    public static RouteHandlerBuilder WithHeaderAugmentation(this RouteHandlerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.AddEndpointFilter(HeaderAugmentationEndpointFilter.Instance);
        return builder;
    }

    private sealed class HeaderAugmentationEndpointFilter : IEndpointFilter
    {
        internal static readonly HeaderAugmentationEndpointFilter Instance = new();

        public async ValueTask<object?> InvokeAsync(
            EndpointFilterInvocationContext context,
            EndpointFilterDelegate next)
        {
            object? result = await next(context);

            if (result is IFileHttpResult
                && !HeaderAugmentationMvcResultFilter.IsExplicitlyTrusted(context.HttpContext))
            {
                HeaderAugmentationDefaults.Apply(context.HttpContext.Response);
            }

            return result;
        }
    }
}
