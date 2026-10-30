namespace CyberShieldHub.Extensions;

public static class CorsExtensions
{
    public const string FrontendPolicy = "Frontend";

    public static IServiceCollection AddCyberShieldCors(this IServiceCollection services) =>
        services.AddCors(options => options.AddPolicy(FrontendPolicy, policy => policy
            .WithOrigins("http://localhost:3000")
            .WithMethods("GET", "POST", "OPTIONS")
            .WithHeaders("Content-Type", "Authorization")
            .WithExposedHeaders("Retry-After", "X-RateLimit-Policy")));
}
