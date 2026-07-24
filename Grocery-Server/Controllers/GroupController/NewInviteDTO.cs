using Grocery_Server.Models;

namespace Grocery_Server.Controllers.GroupController;

public record NewInviteDTO(Guid GroupId, string UserId)
{
    public NewInviteDTO(GroupInvite invite)
        : this(invite.GroupId, invite.UserId) { }

    public GroupInvite GetInvite()
    {
        return new GroupInvite
        {
            CreatedAt = DateTime.UtcNow,
            ExpirationTime = DateTime.UtcNow.AddDays(7),
            GroupId = GroupId,
            UserId = UserId,
        };
    }
}
