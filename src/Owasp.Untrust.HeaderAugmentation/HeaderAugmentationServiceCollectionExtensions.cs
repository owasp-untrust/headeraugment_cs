using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
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
        services.SetupSecureCookies();
        return services;
    }

    /// <summary>
    /// Configures secure cookie defaults and ensures the cookie-policy middleware is active.
    /// </summary>
    /// <param name="services">The application service collection, before the application is built.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection SetupSecureCookies(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Configure<CookiePolicyOptions>(cookiePolicy =>
        {
            cookiePolicy.HttpOnly = HttpOnlyPolicy.Always;
            cookiePolicy.Secure = CookieSecurePolicy.Always;
            cookiePolicy.MinimumSameSitePolicy = SameSiteMode.Strict;
        });
        services.ConfigureApplicationCookie(authentication =>
        {
            authentication.Cookie.HttpOnly = true;
            authentication.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            authentication.Cookie.SameSite = SameSiteMode.Strict;
        });
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IStartupFilter, ConfigureSecureCookiePolicyStartupFilter>());
        return services;
    }

    private sealed class ConfigureHeaderAugmentationMvcOptions : IConfigureOptions<MvcOptions>
    {
        public void Configure(MvcOptions options)
        {
            options.Filters.Add(new HeaderAugmentationMvcResultFilter());
        }
    }

    private sealed class ConfigureSecureCookiePolicyStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => application =>
        {
            application.UseCookiePolicy();
            next(application);
        };
    }
}
