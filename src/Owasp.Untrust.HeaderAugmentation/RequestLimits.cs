using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;

namespace Owasp.Untrust.HeaderAugmentation;

internal static class RequestLimits
{
    internal static void Apply(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Configure<KestrelServerOptions>(options =>
        {
            // Total HTTP request body, across all routes.
            options.Limits.MaxRequestBodySize = 64 * 1024;
        });

        services.Configure<FormOptions>(options =>
        {
            // Multipart/form-data parser limits, across all routes.
            options.MultipartBodyLengthLimit = 32 * 1024; // each part, including IFormFile
            options.ValueLengthLimit = 8 * 1024;          // each ordinary non-file field
            options.ValueCountLimit = 10;                 // number of ordinary form fields

            options.MultipartHeadersCountLimit = 8;       // headers in one multipart part
            options.MultipartHeadersLengthLimit = 8 * 1024; // combined part-header bytes
            options.MultipartBoundaryLengthLimit = 128;   // boundary-token bytes
        });
    }
}
