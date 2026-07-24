using Microsoft.AspNetCore.Identity;
using Microsoft.Identity.Client;

namespace Grocery_Server.Controllers.AuthController;

public record NewUserDTO(string UserName, string Password, string Email, IFormFile? ProfilePicture);
