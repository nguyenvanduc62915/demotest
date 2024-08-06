using System.ComponentModel.DataAnnotations;

namespace DemoTest.DTO
{
    public class LoginDTO
    {
        [Required]
        public string Email { get; set; } = string.Empty;
        [Required]
        public string Password { get; set; } = string.Empty;
    }
}
