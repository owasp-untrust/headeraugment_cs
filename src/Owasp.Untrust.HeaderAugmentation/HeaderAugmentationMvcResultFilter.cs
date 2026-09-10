using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Owasp.Untrust.HeaderAugmentation;

/// <summary>
/// Applies restrictive headers to MVC file results unless the selected endpoint is
/// explicitly marked as trusted.
/// </summary>
public sealed class HeaderAugmentationMvcResultFilter : IAsyncResultFilter
{
    /// <inheritdoc />
    public async Task OnResultExecutionAsync(ResultExecutingContext context, ResultExecutionDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        if (context.Result is FileResult && !IsExplicitlyTrusted(context))
        {
            HeaderAugmentationDefaults.Apply(context.HttpContext.Response);
        }

        await next();
    }

    internal static bool IsExplicitlyTrusted(HttpContext context)
    {
        return context.GetEndpoint()?.Metadata.GetMetadata<TrustedUnblockedOnBrowserFileResponseAttribute>() is not null;
    }

    private static bool IsExplicitlyTrusted(ResultExecutingContext context)
    {
        if (IsExplicitlyTrusted(context.HttpContext))
        {
            return true;
        }

        return context.ActionDescriptor is ControllerActionDescriptor controllerAction
            && (controllerAction.MethodInfo.IsDefined(
                    typeof(TrustedUnblockedOnBrowserFileResponseAttribute),
                    inherit: true)
                || controllerAction.ControllerTypeInfo.IsDefined(
                    typeof(TrustedUnblockedOnBrowserFileResponseAttribute),
                    inherit: true));
    }
}
