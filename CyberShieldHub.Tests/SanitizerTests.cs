using System.Net;
using System.Net.Http.Json;
using CyberShieldHub.Models;
using CyberShieldHub.Services;

namespace CyberShieldHub.Tests;

public sealed class SanitizerTests
{
    [Fact]
    public async Task Homework_example_removes_script_but_preserves_bold_text()
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        using var response = await client.PostAsJsonAsync("/api/feedback", new { comment = "Дякую! <script>alert('XSS')</script><b>Все супер</b>" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<FeedbackResponseDto>();
        Assert.Equal("Дякую! <b>Все супер</b>", body!.SanitizedComment);
        Assert.True(body.IsXssDetected);
    }

    [Theory]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("<b onclick=alert(1)>text</b>")]
    [InlineData("<p onload=alert(1)>text</p>")]
    [InlineData("<iframe src='https://untrusted.example'></iframe>")]
    [InlineData("<object data='x'></object>")]
    [InlineData("<a href='javascript:alert(1)'>click</a>")]
    [InlineData("<a href='java&#x73;cript:alert(1)'>click</a>")]
    [InlineData("<svg><script>alert(1)</script></svg>")]
    [InlineData("<p style='background:url(javascript:alert(1))'>text</p>")]
    public void Dangerous_markup_is_detected_and_removed(string input)
    {
        var service = new XssSanitizerService();
        var clean = service.Sanitize(input);
        Assert.True(service.ContainsDangerousContent(input));
        foreach (var dangerous in new[] { "script", "onerror", "onclick", "onload", "iframe", "object", "svg", "style=" })
            Assert.DoesNotContain(dangerous, clean, StringComparison.OrdinalIgnoreCase);
        Assert.False(service.ContainsDangerousContent(clean));
    }

    [Theory]
    [InlineData("Звичайний коментар")]
    [InlineData("<b>Добре</b><br/>")]
    [InlineData("&lt;script&gt;це звичайний текст&lt;/script&gt;")]
    [InlineData("<a href='https://example.com' title='Посилання'>Сайт</a>")]
    public void Safe_html_and_parser_normalization_are_not_reported_as_xss(string input)
    {
        var service = new XssSanitizerService();
        Assert.False(service.ContainsDangerousContent(input));
        Assert.NotEmpty(service.Sanitize(input));
    }

    [Fact]
    public async Task Singleton_does_not_share_detection_state_between_concurrent_calls()
    {
        var service = new XssSanitizerService();
        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(() =>
        {
            var dangerous = i % 2 == 0;
            var html = dangerous ? "<script>alert(1)</script><b>OK</b>" : "<b>OK</b>";
            Assert.Equal(dangerous, service.ContainsDangerousContent(html));
            Assert.Equal("<b>OK</b>", service.Sanitize(html));
        })));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public async Task Empty_feedback_is_rejected(string comment)
    {
        using var factory = new GatewayFactory();
        using var client = factory.Api();
        using var response = await client.PostAsJsonAsync("/api/feedback", new { comment });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
