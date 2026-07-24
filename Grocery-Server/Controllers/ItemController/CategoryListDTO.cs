namespace Grocery_Server.Controllers.ItemController;

public record CategoryListDTO(Guid Id, string CategoryName, IEnumerable<ItemDisplayDTO> Items)
{
    public CategoryListDTO(Models.GroceryCategory category)
        : this(
            category.Id,
            category.CategoryName,
            category.Items.Select(item => new ItemDisplayDTO(item))
        ) { }
}
