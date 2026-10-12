using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

/*
Then your controllers need no CSRF code at all:
[HttpPost("create")]
public async Task<IActionResult> CreateAsync(
    [FromBody] CreateTaskRequest request)
{
    ...
}

If a specific action intentionally must not require a token:
[HttpPost("some-api-endpoint")]
[IgnoreAntiforgeryToken]
public IActionResult SomeApiEndpoint()
{
    ...
}

You can also exempt an entire controller:
[ApiController]
[IgnoreAntiforgeryToken]
[Route("api")]
public sealed class ExternalApiController : ControllerBase
{
    ...
}

[IgnoreAntiforgeryToken] overrides a global AutoValidateAntiforgeryToken filter. Microsoft Learn


Generating the token
Your existing endpoint can become essentially:
private readonly IAntiforgery _antiforgery;

public AuthenticationController(IAntiforgery antiforgery)
{
    _antiforgery = antiforgery;
}

[HttpGet("gencsrftoken")]
public IActionResult GenerateCsrfToken()
{
    AntiforgeryTokenSet tokens =
        _antiforgery.GetAndStoreTokens(HttpContext);

    return Ok(new
    {
        token = tokens.RequestToken,
        headerName = tokens.HeaderName
    });
}

Then the browser sends:
X-CSRF-TOKEN: <token>

on subsequent unsafe requests.
*/
namespace Owasp.Untrust.HeaderAugmentation;

internal static class AntiforgeryToken
{
    internal static void Apply(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Configure<MvcOptions>(options =>
        {
            options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
        });

        services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN";
        });
    }
}
