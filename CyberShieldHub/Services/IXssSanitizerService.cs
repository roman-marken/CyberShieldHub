namespace CyberShieldHub.Services;

public interface IXssSanitizerService
{
    string Sanitize(string rawHtml);
    bool ContainsDangerousContent(string rawHtml);
}
