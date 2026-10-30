namespace CyberShieldHub.Middleware;

public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            var headers = context.Response.Headers;
            headers["X-Content-Type-Options"] = "nosniff";
            headers["X-Frame-Options"] = "DENY";
            headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
            headers["X-XSS-Protection"] = "0";
            headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
            headers["Cross-Origin-Opener-Policy"] = "same-origin";
            headers["Cross-Origin-Resource-Policy"] = "same-site";
            headers.CacheControl = "no-store";

            // Inline-ініціалізація Scalar потребує окремої політики. Виняток лише для документації.
            var documentation = context.Request.Path.StartsWithSegments("/scalar", StringComparison.OrdinalIgnoreCase)
                || context.Request.Path.StartsWithSegments("/openapi", StringComparison.OrdinalIgnoreCase);
            if (!documentation)
            {
                headers.ContentSecurityPolicy = "default-src 'self'; frame-ancestors 'none'; object-src 'none';";
            }
            return Task.CompletedTask;
        });

        await next(context);
    }
}
