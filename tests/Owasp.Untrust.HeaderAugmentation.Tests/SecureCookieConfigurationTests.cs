using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Owasp.Untrust.HeaderAugmentation.Tests;

public sealed class SecureCookieConfigurationTests
{
    [Fact]
    public void AddHeaderAugmentation_ConfiguresSecureCookieDefaultsAndCookiePolicyMiddleware()
    {
        var services = new ServiceCollection();
        services.AddHeaderAugmentation();
        using ServiceProvider provider = services.BuildServiceProvider();

        CookiePolicyOptions cookiePolicy = provider.GetRequiredService<IOptions<CookiePolicyOptions>>().Value;
        CookieAuthenticationOptions applicationCookie = provider
            .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(IdentityConstants.ApplicationScheme);

        Assert.Equal(HttpOnlyPolicy.Always, cookiePolicy.HttpOnly);
        Assert.Equal(CookieSecurePolicy.Always, cookiePolicy.Secure);
        Assert.Equal(SameSiteMode.Strict, cookiePolicy.MinimumSameSitePolicy);
        Assert.True(applicationCookie.Cookie.HttpOnly);
        Assert.Equal(CookieSecurePolicy.Always, applicationCookie.Cookie.SecurePolicy);
        Assert.Equal(SameSiteMode.Strict, applicationCookie.Cookie.SameSite);
        Assert.NotEmpty(provider.GetServices<IStartupFilter>());
    }
}
