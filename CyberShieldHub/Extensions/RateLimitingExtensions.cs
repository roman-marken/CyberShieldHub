using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace CyberShieldHub.Extensions;

public static class RateLimitingExtensions
{
    public const string LoginPolicy = "login";
    public const string TransfersPolicy = "transfers";

    public static IServiceCollection AddCyberShieldRateLimiting(this IServiceCollection services)
    {
        return services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy(LoginPolicy, context => RateLimitPartition.GetFixedWindowLimiter(
                GetClientIp(context), _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 5,
                    Window = TimeSpan.FromSeconds(60),
                    QueueLimit = 0,
                    AutoReplenishment = true
                }));

            options.AddPolicy(TransfersPolicy, context => RateLimitPartition.GetTokenBucketLimiter(
                GetClientIp(context), _ => new TokenBucketRateLimiterOptions
                {
                    TokenLimit = 10,
                    TokensPerPeriod = 2,
                    ReplenishmentPeriod = TimeSpan.FromSeconds(10),
                    QueueLimit = 0,
                    AutoReplenishment = true
                }));

            options.OnRejected = async (context, cancellationToken) =>
            {
                var http = context.HttpContext;
                var policy = http.GetEndpoint()?.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName;
                var defaultDelay = policy == LoginPolicy ? 60 : 10;
                var seconds = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter)
                    ? Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds)) : defaultDelay;

                http.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                http.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
                http.Response.Headers["X-RateLimit-Policy"] = policy;
                http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("RateLimiting")
                    .LogWarning("Ліміт {Policy} перевищено для IP {ClientIp}", policy, GetClientIp(http));

                await http.Response.WriteAsJsonAsync(new
                {
                    error = "rate_limit_exceeded",
                    message = policy == LoginPolicy
                        ? "Забагато спроб входу. Дозволено 5 спроб за 60 секунд."
                        : "Ліміт переказів вичерпано. Поповнення — 2 запити кожні 10 секунд.",
                    retryAfterSeconds = seconds,
                    policy
                }, cancellationToken);
            };
        });
    }

    private static string GetClientIp(HttpContext context)
    {
        var address = context.Connection.RemoteIpAddress;
        if (address?.IsIPv4MappedToIPv6 == true) address = address.MapToIPv4();
        return address?.ToString() ?? "unknown";
    }
}
