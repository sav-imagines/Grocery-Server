namespace Grocery_Server.Controllers.ItemController;

public class CategoryListDTO
{
    public Guid Id { get; set; }
    public string CategoryName { get; set; }
    public IEnumerable<ItemDisplayDTO> Items { get; set; }

    public CategoryListDTO(Models.GroceryCategory category)
    {
        Id = category.Id;
        CategoryName = category.CategoryName;
        Items = category.Items.Select(item => new ItemDisplayDTO(item));
    }

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
    public CategoryListDTO() { }
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
}
