using System.Security.Cryptography;
using CyberShieldHub.Extensions;
using CyberShieldHub.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = 64 * 1024;
});

builder.Services.AddCyberShieldCors();
builder.Services.AddCyberShieldRateLimiting();
builder.Services.AddSingleton<IXssSanitizerService, XssSanitizerService>();

// Ключ лише в пам'яті: демонстраційні JWT стають недійсними після перезапуску.
var signingKey = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
builder.Services.AddSingleton(signingKey);
builder.Services.AddSingleton<DemoAuthService>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.MapInboundClaims = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = DemoAuthService.Issuer,
        ValidateAudience = true,
        ValidAudience = DemoAuthService.Audience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = signingKey,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero,
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256]
    };
});
builder.Services.AddAuthorization();
builder.Services.AddProblemDetails();
builder.Services.AddControllers();
builder.Services.AddOpenApi(options => options.AddDocumentTransformer((document, _, _) =>
{
    document.Components ??= new OpenApiComponents();
    document.Components.SecuritySchemes = new Dictionary<string, IOpenApiSecurityScheme>
    {
        ["Bearer"] = new OpenApiSecurityScheme { Type = SecuritySchemeType.Http, Scheme = "bearer", BearerFormat = "JWT" }
    };
    foreach (var path in document.Paths.Where(path => path.Key.StartsWith("/api/banking", StringComparison.Ordinal)))
    {
        foreach (var operation in path.Value.Operations!.Values)
        {
            operation.Security = [new OpenApiSecurityRequirement { [new OpenApiSecuritySchemeReference("Bearer", document)] = [] }];
        }
    }
    return Task.CompletedTask;
}));

var app = builder.Build();
app.UseCyberShieldSecurityHeaders();
app.UseExceptionHandler();
app.UseRouting();
app.UseCors(CorsExtensions.FrontendPolicy);
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();

if (app.Environment.IsDevelopment() || app.Environment.IsEnvironment("Testing"))
{
    app.MapOpenApi();
    app.MapScalarApiReference(options => options.WithTitle("CyberShieldHub — Модуль 18"));
    app.MapGet("/", () => Results.Redirect("/scalar/v1")).ExcludeFromDescription();
}

app.MapControllers();
app.Run();

public partial class Program;
