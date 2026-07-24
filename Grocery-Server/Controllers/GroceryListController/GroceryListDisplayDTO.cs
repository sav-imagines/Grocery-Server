using Grocery_Server.Models;

namespace Grocery_Server.Controllers.GroceryListController;

public record GroceryListDisplayDTO(Guid ListId, DateTime CreatedTime, int ItemsCount)
{
    public GroceryListDisplayDTO(GroceryList list)
        : this(list.Id, list.CreationTime, list.GroceryListItems?.Count ?? 0) { }
}
