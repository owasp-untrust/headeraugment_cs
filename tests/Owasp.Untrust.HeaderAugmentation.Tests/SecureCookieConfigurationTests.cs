using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Owasp.Untrust.HeaderAugmentation.Tests;

public sealed class SecureCookieConfigurationTests
{
    [Fact]
    public void AddHeaderAugmentation_ConfiguresSecureDefaults()
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

        Assert.Equal(64 * 1024, provider.GetRequiredService<IOptions<KestrelServerOptions>>().Value.Limits.MaxRequestBodySize);
        FormOptions formOptions = provider.GetRequiredService<IOptions<FormOptions>>().Value;
        Assert.Equal(32 * 1024, formOptions.MultipartBodyLengthLimit);
        Assert.Equal(8 * 1024, formOptions.ValueLengthLimit);
        Assert.Equal(10, formOptions.ValueCountLimit);

        Assert.Equal("X-CSRF-TOKEN", provider.GetRequiredService<IOptions<AntiforgeryOptions>>().Value.HeaderName);
        MvcOptions mvcOptions = provider.GetRequiredService<IOptions<MvcOptions>>().Value;
        Assert.Contains(mvcOptions.Filters, filter => filter is AutoValidateAntiforgeryTokenAttribute);
    }
}
