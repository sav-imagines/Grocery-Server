using Grocery_Server.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Grocery_Server.Controllers.Category;

[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
[EnableRateLimiting(nameof(RateLimiters.Fast))]
[RequireGroup]
[ApiController]
[Route("api/category")]
public class CategoryController : ControllerBase
{
    private readonly GroceryDbContext _dbContext;
    private readonly UserManager<User> _userManager;

    public CategoryController(GroceryDbContext dbContext, UserManager<User> userManager)
    {
        _dbContext = dbContext;
        _userManager = userManager;
    }

    [HttpGet("all")]
    public async Task<IActionResult> GetAll()
    {
        Group group =
            (await GetCurrentUser()).Group
            ?? throw new ArgumentException("how??? attribute not working wth");

        IEnumerable<CategoryDisplayDTO> categories = group.CustomCategories.Select(
            cat => new CategoryDisplayDTO(cat)
        );
        return Ok(categories);
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] string name)
    {
        User user = await GetCurrentUser();
        Group group = GetGroup(user);

        if (group.CustomCategories.Any(cat => cat.CategoryName == name))
            return Conflict("A category with this name already exists.");

        group.CustomCategories.Add(new GroceryCategory(name, group.Id));
        await _dbContext.SaveChangesAsync();
        return Ok();
    }

    [HttpDelete]
    public async Task<IActionResult> Delete([FromQuery] Guid id)
    {
        User user = await GetCurrentUser();
        Group group = GetGroup(user);

        GroceryCategory? foundCategory = group.CustomCategories.FirstOrDefault(cat => cat.Id == id);
        if (foundCategory == null)
            return NotFound();
        _dbContext.Remove(foundCategory);
        await _dbContext.SaveChangesAsync();
        return Ok();
    }

    [HttpPatch("rename")]
    public async Task<IActionResult> Rename([FromBody] RenameCategoryDTO renameInfo)
    {
        User user = await GetCurrentUser();
        Group group = GetGroup(user);

        GroceryCategory? foundCategory = group.CustomCategories.FirstOrDefault(cat =>
            cat.Id == renameInfo.Id
        );
        if (foundCategory == null)
            return NotFound();
        foundCategory.CategoryName = renameInfo.Name;
        await _dbContext.SaveChangesAsync();
        return Ok();
    }

    private async Task<User> GetCurrentUser()
    {
        return await _userManager.GetUserAsync(User)
            ?? throw new Exception(
                "Can't get a user even though it's being used in a [RequireGroup] class????"
            );
    }

    private Group GetGroup(User user)
    {
        return user.Group ?? throw new Exception("Should never happen");
    }
}
