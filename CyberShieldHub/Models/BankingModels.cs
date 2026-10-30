using System.ComponentModel.DataAnnotations;

namespace CyberShieldHub.Models;

public sealed class LoginRequest
{
    [Required, StringLength(100)]
    public string Username { get; set; } = string.Empty;

    [Required, StringLength(200)]
    public string Password { get; set; } = string.Empty;
}

public sealed record LoginResponse(string AccessToken, string TokenType, int ExpiresInSeconds);
public sealed record AccountResponse(int Id, string Name, decimal Balance, string Currency);

public sealed class CreateTransferRequest
{
    [Range(1, int.MaxValue)]
    public int FromAccountId { get; set; }

    [Range(1, int.MaxValue)]
    public int ToAccountId { get; set; }

    [Range(typeof(decimal), "0.01", "1000000", ParseLimitsInInvariantCulture = true, ConvertValueInInvariantCulture = true)]
    public decimal Amount { get; set; }
}

public sealed record TransferResponse(Guid Id, string Status, decimal Amount, string Currency);
