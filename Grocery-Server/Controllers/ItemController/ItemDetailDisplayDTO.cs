namespace Grocery_Server.Controllers.ItemController;

public record ItemDetailDisplayDTO(
    Guid Id,
    string Name,
    DateTime CreatedAt,
    string CategoryName,
    Guid CategoryId
)
{
    public ItemDetailDisplayDTO(Models.GroceryItem item)
        : this(
            item.Id,
            item.ItemName,
            item.CreationTime,
            item.Category.CategoryName,
            item.CategoryId
        ) { }
}
