namespace Grocery_Server.Controllers.AuthController;

public record LoginDTO
{
    public required string UserName { get; set; }
    public required string Password { get; set; }
}
