using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace CyberShieldHub.Tests;

public sealed class GatewayFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureServices(services =>
        {
            services.AddSingleton<IStartupFilter, TestIpFilter>();
            services.AddControllers().AddApplicationPart(typeof(FailureTestController).Assembly);
        });
    }

    public HttpClient Api() => CreateClient(new() { BaseAddress = new Uri("https://localhost") });

    // Заміна мережевого з'єднання лише у тестовій збірці. У звичайному API такого заголовка немає.
    private sealed class TestIpFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, continuation) =>
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse(context.Request.Headers["X-Test-Ip"].FirstOrDefault() ?? "203.0.113.10");
                return continuation(context);
            });
            next(app);
        };
    }
}

[ApiController]
[Route("test-only/failure")]
public sealed class FailureTestController : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => throw new InvalidOperationException("internal-test-details");
}
