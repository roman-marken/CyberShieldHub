using System.ComponentModel.DataAnnotations;

namespace CyberShieldHub.Models;

public sealed class CreateFeedbackRequest
{
    [Required(ErrorMessage = "Вкажіть коментар.")]
    [StringLength(4000, ErrorMessage = "Коментар має містити не більше 4000 символів.")]
    public string Comment { get; set; } = string.Empty;
}

public sealed record FeedbackResponseDto(string SanitizedComment, bool IsXssDetected);
