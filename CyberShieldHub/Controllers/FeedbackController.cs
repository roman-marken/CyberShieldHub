using CyberShieldHub.Models;
using CyberShieldHub.Services;
using Microsoft.AspNetCore.Mvc;

namespace CyberShieldHub.Controllers;

[ApiController]
[Route("api/feedback")]
public sealed class FeedbackController(IXssSanitizerService sanitizer) : ControllerBase
{
    [HttpPost]
    public ActionResult<FeedbackResponseDto> Create(CreateFeedbackRequest request) =>
        Ok(new FeedbackResponseDto(sanitizer.Sanitize(request.Comment), sanitizer.ContainsDangerousContent(request.Comment)));
}
