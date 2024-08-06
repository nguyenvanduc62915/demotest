using DemoTest.DTO;
using DemoTest.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace DemoTest.Controllers;

[ApiController]
[Route("api/[controller]")]
public class RolesController : ControllerBase
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<AppUser> _userManager;

    public RolesController(RoleManager<IdentityRole> roleManager, UserManager<AppUser> userManager)
    {
        _roleManager = roleManager;
        _userManager = userManager;
    }

    [HttpPost]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleDTO createRoleDTO)
    {
        if (string.IsNullOrEmpty(createRoleDTO.RoleName))
        {
            return BadRequest("Role name is required");
        }

        var roleExist = await _roleManager.RoleExistsAsync(createRoleDTO.RoleName);

        if (roleExist)
        { 
            return BadRequest("Role already exist");
        }

        var roleResult = await _roleManager.CreateAsync(new IdentityRole(createRoleDTO.RoleName));

        if (roleResult.Succeeded)
        {
            return Ok(new { message = "Role Created successfully" });
        }

        return BadRequest("Role creation failed.");
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<CreateRoleDTO>>> GetRoles()
    {
        var roles = await _roleManager.Roles.Select(r => new RoleResponseDTO
        {
            Id = r.Id,
            Name = r.Name,
            TotalUsers = _userManager.GetUsersInRoleAsync(r.Name!).Result.Count
        }).ToListAsync();

        return Ok(roles);
    }
} 