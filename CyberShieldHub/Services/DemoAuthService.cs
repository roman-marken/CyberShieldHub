using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using CyberShieldHub.Models;

namespace CyberShieldHub.Services;

public sealed class DemoAuthService(SymmetricSecurityKey signingKey)
{
    public const string Issuer = "CyberShieldHub";
    public const string Audience = "CyberShieldHub.Frontend";
    private readonly PasswordHasher<string> hasher = new();
    // Відкриті навчальні реквізити. Обліковий запис не пов'язаний із реальним банком.
    private readonly string passwordHash = new PasswordHasher<string>().HashPassword("demo", "Demo!2026");

    public LoginResponse? Login(string username, string password)
    {
        var verified = hasher.VerifyHashedPassword("demo", passwordHash, password);
        if (username != "demo" || verified == PasswordVerificationResult.Failed) return null;

        var token = new JwtSecurityToken(
            issuer: Issuer,
            audience: Audience,
            claims: [new Claim(JwtRegisteredClaimNames.Sub, "demo"), new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())],
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(15),
            signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256));
        return new LoginResponse(new JwtSecurityTokenHandler().WriteToken(token), "Bearer", 900);
    }
}
