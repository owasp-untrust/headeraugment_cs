using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Xunit;

namespace Owasp.Untrust.HeaderAugmentation.Tests;

public sealed class HeaderAugmentationMvcResultFilterTests
{
    private static readonly HeaderAugmentationMvcResultFilter Filter = new();

    [Fact]
    public async Task FileContentResultReceivesRestrictiveHeaders()
    {
        DefaultHttpContext httpContext = await ExecuteAsync(new FileContentResult([], "image/png"));

        Assert.Equal(HeaderAugmentationDefaults.ContentSecurityPolicy,
            httpContext.Response.Headers["Content-Security-Policy"]);
        Assert.Equal("nosniff", httpContext.Response.Headers["X-Content-Type-Options"]);
    }

    [Fact]
    public async Task SvgFileContentResultReceivesRestrictiveHeaders()
    {
        DefaultHttpContext httpContext = await ExecuteAsync(new FileContentResult([], "image/svg+xml"));

        Assert.Equal(HeaderAugmentationDefaults.ContentSecurityPolicy,
            httpContext.Response.Headers["Content-Security-Policy"]);
    }

    [Fact]
    public async Task FileStreamResultReceivesRestrictiveHeaders()
    {
        DefaultHttpContext httpContext = await ExecuteAsync(new FileStreamResult(Stream.Null, "application/octet-stream"));

        Assert.Equal(HeaderAugmentationDefaults.ContentSecurityPolicy,
            httpContext.Response.Headers["Content-Security-Policy"]);
    }

    [Fact]
    public async Task FilePathResultReceivesRestrictiveHeaders()
    {
        DefaultHttpContext httpContext = await ExecuteAsync(new PhysicalFileResult("C:\\files\\example.txt", "text/plain"));

        Assert.Equal(HeaderAugmentationDefaults.ContentSecurityPolicy,
            httpContext.Response.Headers["Content-Security-Policy"]);
    }

    [Fact]
    public async Task NonFileResultDoesNotReceiveHeaders()
    {
        DefaultHttpContext httpContext = await ExecuteAsync(new JsonResult(new { status = "ok" }));

        Assert.False(httpContext.Response.Headers.ContainsKey("Content-Security-Policy"));
        Assert.False(httpContext.Response.Headers.ContainsKey("X-Content-Type-Options"));
    }

    [Fact]
    public async Task TrustedFileResultDoesNotReceiveDefaultHeaders()
    {
        DefaultHttpContext httpContext = new();
        httpContext.SetEndpoint(CreateEndpoint(new TrustedUnblockedOnBrowserFileResponseAttribute("Reviewed test file.")));

        await ExecuteAsync(new FileContentResult([], "image/svg+xml"), httpContext);

        Assert.False(httpContext.Response.Headers.ContainsKey("Content-Security-Policy"));
        Assert.False(httpContext.Response.Headers.ContainsKey("X-Content-Type-Options"));
    }

    [Fact]
    public async Task ApplicationDefinedPolicyIsPreserved()
    {
        DefaultHttpContext httpContext = new();
        httpContext.Response.Headers["Content-Security-Policy"] = "default-src 'self'";

        await ExecuteAsync(new FileContentResult([], "image/png"), httpContext);

        Assert.Equal("default-src 'self'", httpContext.Response.Headers["Content-Security-Policy"]);
        Assert.Equal("nosniff", httpContext.Response.Headers["X-Content-Type-Options"]);
    }

    private static async Task<DefaultHttpContext> ExecuteAsync(
        IActionResult result,
        DefaultHttpContext? existingContext = null)
    {
        DefaultHttpContext httpContext = existingContext ?? new DefaultHttpContext();
        ActionContext actionContext = new(httpContext, new RouteData(), new ActionDescriptor());
        List<IFilterMetadata> filters = [];
        ResultExecutingContext executingContext = new(actionContext, filters, result, new object());

        await Filter.OnResultExecutionAsync(
            executingContext,
            () => Task.FromResult(new ResultExecutedContext(actionContext, filters, result, new object())));

        return httpContext;
    }

    private static RouteEndpoint CreateEndpoint(object metadata)
    {
        return new RouteEndpoint(
            static _ => Task.CompletedTask,
            RoutePatternFactory.Parse("/file"),
            0,
            new EndpointMetadataCollection(metadata),
            "trusted-file");
    }
}
