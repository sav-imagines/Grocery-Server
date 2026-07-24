using Grocery_Server.Models;

namespace Grocery_Server.Controllers.GroupController;

public record InviteDisplayDTO(
    Guid GroupId,
    string UserId,
    string UserName,
    string GroupName,
    DateTime CreatedAt,
    DateTime ExpiresAt,
    int GroupMemberCount
)
{
    public InviteDisplayDTO(GroupInvite invite)
        : this(
            invite.GroupId,
            invite.UserId,
            invite.User?.UserName ?? "",
            invite.Group.Name,
            invite.CreatedAt,
            invite.ExpirationTime,
            invite.Group.Members.Count
        ) { }
}
