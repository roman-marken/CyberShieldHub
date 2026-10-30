using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using CyberShieldHub.Models;

namespace CyberShieldHub.Tests;

public sealed class ProtectionTests
{
    [Fact]
    public async Task Sixth_login_is_429_with_retry_after_and_security_headers()
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        for (var i = 0; i < 5; i++)
        {
            using var attempt = await WrongLogin(client);
            Assert.Equal(HttpStatusCode.Unauthorized, attempt.StatusCode);
        }
        using var response = await WrongLogin(client);
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        var seconds = int.Parse(response.Headers.GetValues("Retry-After").Single());
        Assert.InRange(seconds, 1, 60);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("rate_limit_exceeded", body.GetProperty("error").GetString());
        Assert.Equal(seconds, body.GetProperty("retryAfterSeconds").GetInt32());
        Assert.Equal("login", body.GetProperty("policy").GetString());
        AssertSecurityHeaders(response);

        client.DefaultRequestHeaders.Add("X-Forwarded-For", "198.51.100.99");
        using var forged = await WrongLogin(client);
        Assert.Equal(HttpStatusCode.TooManyRequests, forged.StatusCode);
        client.DefaultRequestHeaders.Add("X-Test-Ip", "203.0.113.11");
        using var otherIp = await WrongLogin(client);
        Assert.Equal(HttpStatusCode.Unauthorized, otherIp.StatusCode);
    }

    [Fact]
    public async Task Successful_and_invalid_body_logins_also_consume_permits()
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        using var success = await client.PostAsJsonAsync("/api/auth/login", new { username = "demo", password = "Demo!2026" });
        Assert.Equal(HttpStatusCode.OK, success.StatusCode);
        for (var i = 0; i < 4; i++)
        {
            using var invalid = await client.PostAsJsonAsync("/api/auth/login", new { username = "" });
            Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        }
        using var limited = await WrongLogin(client);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
    }

    [Fact]
    public async Task Transfers_allow_ten_then_refill_exactly_two_tokens()
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        await Authenticate(client);
        for (var i = 0; i < 10; i++)
        {
            using var transfer = await Transfer(client);
            Assert.Equal(HttpStatusCode.OK, transfer.StatusCode);
            Assert.Equal("Simulated", (await transfer.Content.ReadFromJsonAsync<TransferResponse>())!.Status);
        }
        using var rejected = await Transfer(client);
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.InRange(int.Parse(rejected.Headers.GetValues("Retry-After").Single()), 1, 10);
        Assert.Equal("transfers", rejected.Headers.GetValues("X-RateLimit-Policy").Single());
        AssertSecurityHeaders(rejected);

        // Чекаємо реального поповнення вбудованого Token Bucket, без заміни реалізації.
        await Task.Delay(TimeSpan.FromSeconds(10.3));
        using var first = await Transfer(client);
        using var second = await Transfer(client);
        using var third = await Transfer(client);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
    }

    [Fact]
    public async Task Login_and_transfer_limits_are_independent_and_transfers_are_partitioned_by_ip()
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        await Authenticate(client);
        for (var i = 0; i < 5; i++) await WrongLogin(client);
        using var transfer = await Transfer(client);
        Assert.Equal(HttpStatusCode.OK, transfer.StatusCode);
        for (var i = 0; i < 9; i++) await Transfer(client);
        using var blocked = await Transfer(client);
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        client.DefaultRequestHeaders.Add("X-Test-Ip", "203.0.113.42");
        using var other = await Transfer(client);
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
    }

    [Fact]
    public async Task Banking_requires_valid_token_and_rejects_other_source_account()
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        using var anonymous = await client.GetAsync("/api/banking/accounts");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        AssertSecurityHeaders(anonymous);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "fake-token");
        using var forged = await client.GetAsync("/api/banking/accounts");
        Assert.Equal(HttpStatusCode.Unauthorized, forged.StatusCode);
        await Authenticate(client);
        using var accounts = await client.GetAsync("/api/banking/accounts");
        Assert.Equal(HttpStatusCode.OK, accounts.StatusCode);
        AssertSecurityHeaders(accounts);
        using var forbidden = await client.PostAsJsonAsync("/api/banking/transfers", new { fromAccountId = 2, toAccountId = 1, amount = 10 });
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
    }

    [Fact]
    public async Task Cors_allows_only_frontend_and_exposes_retry_headers()
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        using var allowed = new HttpRequestMessage(HttpMethod.Get, "/api/banking/accounts");
        allowed.Headers.Add("Origin", "http://localhost:3000");
        using var response = await client.SendAsync(allowed);
        Assert.Equal("http://localhost:3000", response.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.Contains("retry-after", string.Join(',', response.Headers.GetValues("Access-Control-Expose-Headers")), StringComparison.OrdinalIgnoreCase);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));

        using var denied = new HttpRequestMessage(HttpMethod.Get, "/api/banking/accounts");
        denied.Headers.Add("Origin", "https://untrusted.example");
        using var blocked = await client.SendAsync(denied);
        Assert.False(blocked.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task Preflight_is_allowed_and_does_not_exhaust_login_policy()
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        for (var i = 0; i < 6; i++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Options, "/api/auth/login");
            request.Headers.Add("Origin", "http://localhost:3000");
            request.Headers.Add("Access-Control-Request-Method", "POST");
            request.Headers.Add("Access-Control-Request-Headers", "content-type");
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            Assert.Equal("http://localhost:3000", response.Headers.GetValues("Access-Control-Allow-Origin").Single());
            AssertSecurityHeaders(response);
        }
        using var login = await WrongLogin(client);
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
    }

    [Fact]
    public async Task Rate_limited_responses_keep_cors_headers()
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        client.DefaultRequestHeaders.Add("Origin", "http://localhost:3000");
        for (var i = 0; i < 5; i++) await WrongLogin(client);
        using var blocked = await WrongLogin(client);
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.Equal("http://localhost:3000", blocked.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.True(blocked.Headers.Contains("Access-Control-Expose-Headers"));
    }

    [Theory]
    [InlineData("/not-found", HttpStatusCode.NotFound)]
    [InlineData("/test-only/failure", HttpStatusCode.InternalServerError)]
    [InlineData("/scalar-fake", HttpStatusCode.NotFound)]
    public async Task Security_headers_cover_errors_and_do_not_leak_exception(string path, HttpStatusCode status)
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        using var response = await client.GetAsync(path);
        Assert.Equal(status, response.StatusCode);
        AssertSecurityHeaders(response);
        Assert.DoesNotContain("internal-test-details", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("/scalar/v1")]
    [InlineData("/openapi/v1.json")]
    public async Task Documentation_keeps_headers_without_restrictive_csp(string path)
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        using var response = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("Content-Security-Policy"));
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
    }

    [Fact]
    public async Task Openapi_documents_bearer_security_and_limited_routes()
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        var schema = await client.GetFromJsonAsync<JsonElement>("/openapi/v1.json");
        Assert.Equal("bearer", schema.GetProperty("components").GetProperty("securitySchemes").GetProperty("Bearer").GetProperty("scheme").GetString());
        var transfer = schema.GetProperty("paths").GetProperty("/api/banking/transfers").GetProperty("post");
        Assert.True(transfer.GetProperty("responses").TryGetProperty("429", out _));
        Assert.True(transfer.GetProperty("security")[0].TryGetProperty("Bearer", out _));
    }

    private static Task<HttpResponseMessage> WrongLogin(HttpClient client) =>
        client.PostAsJsonAsync("/api/auth/login", new { username = "demo", password = "wrong" });

    private static Task<HttpResponseMessage> Transfer(HttpClient client) =>
        client.PostAsJsonAsync("/api/banking/transfers", new { fromAccountId = 1, toAccountId = 2, amount = 10 });

    private static async Task Authenticate(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username = "demo", password = "Demo!2026" });
        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<LoginResponse>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token!.AccessToken);
    }

    private static void AssertSecurityHeaders(HttpResponseMessage response)
    {
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("default-src 'self'; frame-ancestors 'none'; object-src 'none';", response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("strict-origin-when-cross-origin", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Equal("0", response.Headers.GetValues("X-XSS-Protection").Single());
        Assert.True(response.Headers.Contains("Permissions-Policy"));
        Assert.True(response.Headers.Contains("Cross-Origin-Opener-Policy"));
        Assert.True(response.Headers.Contains("Cross-Origin-Resource-Policy"));
        Assert.True(response.Headers.CacheControl!.NoStore);
    }
}
