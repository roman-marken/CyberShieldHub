using CyberShieldHub.Extensions;
using CyberShieldHub.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace CyberShieldHub.Controllers;

[ApiController]
[Authorize]
[Route("api/banking")]
public sealed class BankingController : ControllerBase
{
    [HttpGet("accounts")]
    public ActionResult<AccountResponse[]> Accounts() =>
        Ok(new[] { new AccountResponse(1, "Демонстраційний рахунок", 10000, "UAH") });

    [HttpPost("transfers")]
    [EnableRateLimiting(RateLimitingExtensions.TransfersPolicy)]
    [ProducesResponseType<TransferResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public ActionResult<TransferResponse> Transfer(CreateTransferRequest request)
    {
        if (request.FromAccountId != 1) return Forbid();
        if (request.ToAccountId != 2 || request.Amount > 10000)
            return BadRequest(new { message = "Вкажіть рахунок отримувача 2 і суму до 10000 UAH." });

        // Навчальна імітація: кошти не списуються, баланс не змінюється.
        return Ok(new TransferResponse(Guid.NewGuid(), "Simulated", request.Amount, "UAH"));
    }
}
