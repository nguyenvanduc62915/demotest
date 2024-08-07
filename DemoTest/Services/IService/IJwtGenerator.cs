using DemoTest.Models;

namespace DemoTest.Services.IService
{
    public interface IJwtGenerator
    {
        string CreateToken(AppUser user, IList<string> roles);
    }
}
