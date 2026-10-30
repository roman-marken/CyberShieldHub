using Ganss.Xss;

namespace CyberShieldHub.Services;

// Singleton не має змінного стану: парсер і події створюються окремо для кожного виклику.
public sealed class XssSanitizerService : IXssSanitizerService
{
    public string Sanitize(string rawHtml) => CreateSanitizer().Sanitize(rawHtml);

    public bool ContainsDangerousContent(string rawHtml)
    {
        var detected = false;
        var sanitizer = CreateSanitizer();
        sanitizer.RemovingTag += (_, _) => detected = true;
        sanitizer.RemovingAttribute += (_, _) => detected = true;
        sanitizer.Sanitize(rawHtml);
        return detected;
    }

    private static HtmlSanitizer CreateSanitizer()
    {
        var sanitizer = new HtmlSanitizer { KeepChildNodes = false };
        sanitizer.AllowedTags.Clear();
        sanitizer.AllowedTags.UnionWith(["b", "strong", "i", "em", "u", "p", "br", "ul", "ol", "li", "a", "blockquote", "code"]);
        sanitizer.AllowedAttributes.Clear();
        sanitizer.AllowedAttributes.UnionWith(["href", "title"]);
        sanitizer.AllowedSchemes.Clear();
        sanitizer.AllowedSchemes.UnionWith(["http", "https", "mailto"]);
        return sanitizer;
    }
}
