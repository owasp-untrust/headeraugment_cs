# OWASP Untrust Header Augmentation for ASP.NET Core

`Owasp.Untrust.HeaderAugmentation` applies restrictive browser headers to file
responses by default. It protects MVC `FileResult` values and minimal-API
`IFileHttpResult` values, including SVG files. JSON, HTML, and other non-file
responses are not changed.

## MVC registration

Register once after MVC services are added:

```csharp
builder.Services.AddControllersWithViews();
builder.Services.AddHeaderAugmentation();
```

Activating HeaderAugmentation also configures secure cookie defaults and adds
`UseCookiePolicy()` to the application pipeline: all cookies are HTTP-only and
secure, with `SameSite=Strict`; the Identity application cookie receives the
same settings. No separate post-build setup call is required.

All MVC `FileResult` variants receive:

```text
Content-Security-Policy: sandbox; default-src 'none'; base-uri 'none'; form-action 'none'
X-Content-Type-Options: nosniff
```

## Minimal APIs

Map minimal APIs through one root group. The group filter is inherited by every
endpoint mapped through it, so individual handlers do not need to remember an
opt-in call:

```csharp
RouteGroupBuilder api = app.MapHeaderAugmentationGroup();
api.MapGet("/files/{id}", GetFile);
api.MapGet("/health", GetHealth);
```

The filter only augments `IFileHttpResult` values; non-file responses remain
unchanged. Use `WithHeaderAugmentation()` on a smaller group when only part of
the minimal-API surface should participate.

## Explicit trusted exception

Use the trusted attribute only after deliberate review. Its non-blank
justification makes the exception auditable:

```csharp
[TrustedUnblockedOnBrowserFileResponse(
    "The application generates this fixed SVG from server-owned data.")]
public IActionResult BrandingLogo()
{
    return File(svgBytes, "image/svg+xml");
}
```

The attribute opts out of this library's default headers. Existing application
headers are preserved and never overwritten.

## Static files

Files served by `UseStaticFiles()` do not execute MVC result filters or minimal
API endpoint filters. Configure restrictive headers in `StaticFileOptions` for
those files, or serve security-sensitive files through a protected endpoint.
