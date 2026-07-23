//using Grocery_Server.ControllerModels;
using System;
using Grocery_Server.Controllers.Category;
using Grocery_Server.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace Grocery_Server.Controllers.ItemController;

[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
[Route("api/item")]
[EnableRateLimiting(nameof(RateLimiters.Fast))]
[RequireGroup]
//TODO: re-evaluate rate limiters to allow for ReallyFast searches
public class ItemController : ControllerBase
{
    private readonly GroceryDbContext _dbContext;
    private readonly UserManager<User> _userManager;

    public ItemController([FromServices] GroceryDbContext dbContext, UserManager<User> userManager)
    {
        _dbContext = dbContext;
        _userManager = userManager;
    }

    [HttpPost]
    public async Task<IActionResult> CreateItem([FromBody] NewItemDTO itemDTO)
    {
        if (itemDTO.Name.Trim().IsNullOrEmpty())
            return BadRequest();

        User user = await GetCurrentUser();
        Group group = user.Group ?? throw new Exception("Should be included already");

        GroceryCategory? category = group.CustomCategories.FirstOrDefault(cat =>
            cat.Id == itemDTO.CategoryId
        );
        if (category == null)
            return BadRequest();

        if (category.Items.Any(item => item.ItemName == itemDTO.Name))
            return Conflict("Item already exists in category");

        GroceryItem newItem = new(itemDTO);
        newItem.ItemName = newItem.ItemName.Trim().ToLower();
        newItem.ItemName = char.ToUpper(newItem.ItemName[0]) + newItem.ItemName[1..];
        _dbContext.GroceryItems.Add(newItem);
        await _dbContext.SaveChangesAsync();
        return Ok(newItem.Id);
    }

    [HttpGet("by-group")]
    public async Task<IActionResult> GetItemsFromGroup()
    {
        User user = await GetCurrentUser();
        Group group = user.Group ?? throw new Exception("Should be included already");

        return Ok(group.CustomCategories.Select(category => new CategoryListDTO(category)));
    }

    [HttpGet("by-id")]
    public async Task<IActionResult> GetItemById([FromQuery] Guid id)
    {
        User user = await GetCurrentUser();
        Group group = user.Group ?? throw new Exception("Should be included already");

        GroceryItem? foundItem = _dbContext.GroceryItems.FirstOrDefault(item => item.Id == id);
        if (foundItem == null)
            return NotFound();
        if (foundItem.Category.Group != group) // act like item does not exist if unowned
            return NotFound();
        return Ok(new ItemDetailDisplayDTO(foundItem));
    }

    [HttpGet("by-category")]
    public async Task<IActionResult> GetItemsInCategory([FromQuery] Guid id)
    {
        User user = await GetCurrentUser();
        Group group = user.Group ?? throw new Exception("Should be included already");

        GroceryCategory? category = group.CustomCategories.FirstOrDefault(category =>
            category.Id == id
        );
        if (category == null)
            return NotFound();
        return Ok(new CategoryListDTO(category));
    }

    [EnableRateLimiting(nameof(RateLimiters.Slow))]
    [HttpPatch("rename")]
    public async Task<IActionResult> RenameItem([FromBody] RenameCategoryDTO renamedItem)
    {
        GroceryItem? toRenameItem = _dbContext.GroceryItems.FirstOrDefault(item =>
            item.Id == renamedItem.Id
        );
        if (toRenameItem == null)
            return NotFound();
        toRenameItem.ItemName = renamedItem.Name;
        await _dbContext.SaveChangesAsync();
        return Ok(new ItemDetailDisplayDTO(toRenameItem));
    }

    [EnableRateLimiting(nameof(RateLimiters.Slow))]
    [HttpDelete("delete")]
    public async Task<IActionResult> DeleteItem([FromQuery] Guid id)
    {
        User user = await GetCurrentUser();
        Group group = user.Group ?? throw new Exception("Should be included already");

        GroceryItem? existingItem = _dbContext.GroceryItems.FirstOrDefault(item => item.Id == id);
        if (existingItem == null || existingItem.Category.GroupId != group.Id)
            return NotFound();
        _dbContext.GroceryItems.Remove(existingItem);
        await _dbContext.SaveChangesAsync();
        return Ok();
    }

    [HttpGet("search/{query}")]
    public async Task<IActionResult> SearchItem(string query)
    {
        User user = await GetCurrentUser();

        IEnumerable<ItemDetailDisplayDTO> items = _dbContext
            .GroceryItems.Where(item => EF.Functions.ILike(item.ItemName, $"%{query}%"))
            .Where(item => item.Category.GroupId == user.GroupId)
            .Include(item => item.Category)
            .Select(item => new ItemDetailDisplayDTO(item));
        return Ok(items);
    }

    private async Task<User> GetCurrentUser()
    {
        User? user =
            await _userManager.GetUserAsync(User) ?? throw new Exception("Should be impossible");
        await _dbContext.Entry(user).Reference(u => u.Group).LoadAsync();
        return user;
    }
}
