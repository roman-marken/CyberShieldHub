using CyberShieldHub.Extensions;
using CyberShieldHub.Models;
using CyberShieldHub.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace CyberShieldHub.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController(DemoAuthService auth) : ControllerBase
{
    [HttpPost("login")]
    [EnableRateLimiting(RateLimitingExtensions.LoginPolicy)]
    [ProducesResponseType<LoginResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public ActionResult<LoginResponse> Login(LoginRequest request)
    {
        var result = auth.Login(request.Username, request.Password);
        return result is null ? Unauthorized(new { message = "Неправильний логін або пароль." }) : Ok(result);
    }
}
