using Grocery_Server.Models;

namespace Grocery_Server.Controllers.RecipeController;

public record RecipeInfoDTO(
    Guid Id,
    string Name,
    string Description,
    string RecipePictureName,
    string Steps
)
{
    public RecipeInfoDTO(Recipe recipe)
        : this(
            recipe.Id,
            recipe.Name,
            recipe.Description,
            recipe.RecipePictures.FirstOrDefault()?.FileName ?? "",
            recipe.Steps
        ) { }
}
