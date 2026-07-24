namespace Grocery_Server.Controllers.GroceryListController;

public record AddToListItemDTO(Guid ItemId, Guid ListId, ushort Quantity);
