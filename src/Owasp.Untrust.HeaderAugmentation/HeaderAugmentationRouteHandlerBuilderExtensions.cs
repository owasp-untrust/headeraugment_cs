using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Routing;

namespace Owasp.Untrust.HeaderAugmentation;

/// <summary>
/// Provides minimal-API group and endpoint registration for restrictive browser-file headers.
/// </summary>
public static class HeaderAugmentationRouteHandlerBuilderExtensions
{
    /// <summary>
    /// Creates a route group whose endpoints receive restrictive headers for every
    /// <see cref="IFileHttpResult"/> they return, unless the endpoint is explicitly marked as trusted.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="prefix">The route-pattern prefix for the group.</param>
    /// <returns>The configured route group.</returns>
    public static RouteGroupBuilder MapHeaderAugmentationGroup(this IEndpointRouteBuilder endpoints, string prefix = "")
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        RouteGroupBuilder group = endpoints.MapGroup(prefix);
        return group.WithHeaderAugmentation();
    }

    /// <summary>
    /// Adds restrictive headers to <see cref="IFileHttpResult"/> values returned by endpoints
    /// mapped through this builder, unless an endpoint is explicitly marked as trusted.
    /// </summary>
    /// <typeparam name="TBuilder">The endpoint or route-group builder type.</typeparam>
    /// <param name="builder">The builder whose endpoints receive the filter.</param>
    /// <returns>The same builder.</returns>
    public static TBuilder WithHeaderAugmentation<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
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
