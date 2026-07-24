using Grocery_Server.Controllers.UserController;

namespace Grocery_Server.Controllers.GroupController;

public record GroupDisplayDTO(
    Guid? Id,
    IEnumerable<UserDisplayDTO> Members,
    DateTime CreatedAt,
    string Owner
)
{
    public GroupDisplayDTO(Models.Group group)
        : this(
            group.Id,
            group.Members.Select(member => new UserDisplayDTO(member)),
            group.CreationTime,
            group.Owner?.UserName ?? group.Owner?.ToString() ?? "No owner"
        ) { }
}
