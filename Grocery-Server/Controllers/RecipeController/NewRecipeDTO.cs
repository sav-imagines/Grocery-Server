namespace Grocery_Server.Controllers.RecipeController;

public record NewRecipeDTO(
    string Name,
    string Description,
    // encoded as JSON
    //TODO: try storing as a list directly
    string Items,
    string Steps,
    List<IFormFile>? Pictures
);
