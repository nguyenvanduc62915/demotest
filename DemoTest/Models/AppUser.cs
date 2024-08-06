using Microsoft.AspNetCore.Identity;

namespace DemoTest.Models
{
    public class AppUser : IdentityUser
    {
        public string? FullName { get; set; }
    }
}
