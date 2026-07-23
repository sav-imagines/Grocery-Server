using System.Diagnostics.CodeAnalysis;

namespace Grocery_Server.Models;

public class GroceryList
{
    public Guid Id { get; set; }

    public Guid GroupId { get; set; }

    public DateTime CreationTime { get; set; }

    [AllowNull]
    public virtual ICollection<GroceryListItem>? GroceryListItems { get; set; }

    [AllowNull]
    public virtual Group Group { get; set; }

    public GroceryList(Group group)
    {
        Id = new();
        GroupId = group.Id;
        CreationTime = DateTime.UtcNow;
    }

    public GroceryList() { }
}
