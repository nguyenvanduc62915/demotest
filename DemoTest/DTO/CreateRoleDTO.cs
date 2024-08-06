using System.ComponentModel.DataAnnotations;

namespace DemoTest.DTO;

public class CreateRoleDTO
{
    [Required(ErrorMessage = "Role name is required.")]
    public string RoleName { get; set; } = null!;
}