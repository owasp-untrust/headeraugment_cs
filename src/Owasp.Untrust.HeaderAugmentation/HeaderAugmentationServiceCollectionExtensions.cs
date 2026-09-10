using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Owasp.Untrust.HeaderAugmentation;

/// <summary>
/// Provides ASP.NET Core MVC registration for restrictive browser-file headers.
/// </summary>
public static class HeaderAugmentationServiceCollectionExtensions
{
    /// <summary>
    /// Adds a global MVC result filter that protects <see cref="FileResult"/> responses.
    /// </summary>
    /// <param name="services">The application service collection.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddHeaderAugmentation(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<MvcOptions>, ConfigureHeaderAugmentationMvcOptions>());
        return services;
    }

    private sealed class ConfigureHeaderAugmentationMvcOptions : IConfigureOptions<MvcOptions>
    {
        public void Configure(MvcOptions options)
        {
            options.Filters.Add(new HeaderAugmentationMvcResultFilter());
        }
    }
}
