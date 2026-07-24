namespace Grocery_Server.Controllers.UserController;

public record UserDisplayDTO(
    string Id,
    string Name,
    DateTime JoinedAt,
    bool IsInGroup,
    string ProfilePictureName
)
{
    public UserDisplayDTO(Models.User user)
        : this(
            user.Id,
            user.UserName ?? "Name not found",
            user.JoinTime,
            user.GroupId != null,
            user.ProfilePicture?.FileName ?? ""
        ) { }
}
