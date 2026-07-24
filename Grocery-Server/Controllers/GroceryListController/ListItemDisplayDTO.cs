namespace Grocery_Server.Controllers.GroceryListController;

public record ListItemDisplayDTO(
    Guid Id,
    string Name,
    int Quantity,
    Guid CategoryId,
    string CategoryName
);
