using CyberShieldHub.Middleware;

namespace CyberShieldHub.Extensions;

public static class SecurityHeadersExtensions
{
    public static IApplicationBuilder UseCyberShieldSecurityHeaders(this IApplicationBuilder app) =>
        app.UseMiddleware<SecurityHeadersMiddleware>();
}
