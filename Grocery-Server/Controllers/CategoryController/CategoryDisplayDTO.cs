namespace Grocery_Server.Controllers.Category;

public record CategoryDisplayDTO(Guid Id, string Name)
{
    public CategoryDisplayDTO(Models.GroceryCategory category)
        : this(category.Id, category.CategoryName) { }
}
