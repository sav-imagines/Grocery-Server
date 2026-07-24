using Grocery_Server.Models;

namespace Grocery_Server.Controllers.RequestController;

public record RequestListItemDTO(Guid ItemId, ushort Quantity)
{
    public RequestListItemDTO(RequestListItem item)
        : this(item.ItemId, item.Quantity) { }
}
