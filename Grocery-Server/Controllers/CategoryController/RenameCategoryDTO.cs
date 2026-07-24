namespace Grocery_Server.Controllers.Category;

// for renaming an item or category, has an ID and a new name
public record RenameCategoryDTO(Guid Id, string Name);
