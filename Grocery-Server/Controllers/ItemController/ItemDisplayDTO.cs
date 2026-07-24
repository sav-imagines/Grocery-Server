namespace Grocery_Server.Controllers.ItemController;

public record ItemDisplayDTO(Guid Id, string Name)
{
    public ItemDisplayDTO(Models.GroceryItem item)
        : this(item.Id, item.ItemName) { }
}
