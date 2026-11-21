using Microsoft.AspNetCore.Mvc;

namespace Grocery_Server.Controllers.HealthCheckController;


[ApiController]
[Route("api/[controller]")]
public class HealthCheckController : ControllerBase
{
    [HttpGet]
    public IActionResult HealthCheck()
    {
        return Ok();
    }
}
