//using Grocery_Server.ControllerModels;
using Grocery_Server.Models;
using Grocery_Server.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace Grocery_Server.Controllers.GroupController;

[ApiController]
[EnableRateLimiting(nameof(RateLimiters.Fast))]
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
[Route("api/group")]
public class GroupController : ControllerBase
{
    private readonly GroceryDbContext _dbContext;
    private readonly UserManager<User> _userManager;
    private readonly ImageStorageService _imageStorageService;
    public GroupController(GroceryDbContext dbContext, UserManager<User> userManager, ImageStorageService imageStorageService)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _imageStorageService = imageStorageService;
    }

    /// <summary>
    /// Gets your own group's information
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        User? user = await GetCurrentUser();
        if (user == null)
            return Unauthorized();
        return user.Group == null ? NotFound("You're not in a group")
            : Ok(new GroupDisplayDTO(user.Group, _imageStorageService));
    }

    [EnableRateLimiting(nameof(RateLimiters.Slow))]
    [HttpPost("create")]
    public async Task<IActionResult> CreateGroup([FromBody] NewGroupDTO creationModel)
    {
        User? user = await GetCurrentUser();
        if (user == null)
            return Unauthorized();

        Group group = new(user, creationModel.Name);

        if (_dbContext.Groups.Any(house => house.Owner == user))
            return Conflict("You are already the owner of a group"); // can't create new group if already owner of a group

        _dbContext.Groups.Add(group);
        user.GroupId = group.Id;
        await _dbContext.SaveChangesAsync();

        return Ok(group.GetString());
    }

    [EnableRateLimiting(nameof(RateLimiters.Slow))]
    [HttpDelete]
    public async Task<IActionResult> DeleteGroup([FromQuery] Guid id)
    {
        Group? group = await _dbContext.Groups.FirstOrDefaultAsync(group => group.Id == id);
        if (group == null)
            return NotFound();
        _dbContext.Groups.Remove(group);
        await _dbContext.SaveChangesAsync();
        return Ok();
    }

    [EnableRateLimiting(nameof(RateLimiters.Slow))]
    [HttpPost("send-invite")]
    public async Task<IActionResult> SendInvite([FromBody] string invitedId)
    {
        User? inviter = await GetCurrentUser();
        if (inviter == null || inviter.GroupId == null)
            return Unauthorized();
        Guid groupId = (Guid)inviter.GroupId;

        User? addressee = await _dbContext.Users.FirstOrDefaultAsync(user => user.Id == invitedId);
        if (addressee == null)
            return NotFound("No such user exists");

        if (addressee.GroupId != null)
            return BadRequest($"Already a member of group {addressee.Group!.Name}");

        GroupInvite? existingInvite = await _dbContext.GroupInvites.FirstOrDefaultAsync(existingInvite =>
            existingInvite.GroupId == groupId && existingInvite.UserId == invitedId);
        if (existingInvite != null)
        {
            if (!existingInvite.IsExpired()) // if a valid invite still exists, return conflict
                return Conflict("You have already sent an invite to this person");
            else // if existing invite is expired, remove it and continue
                _dbContext.Remove(existingInvite);
        }
        _dbContext.GroupInvites.Add(new GroupInvite(invitedId, groupId, inviter.Id));
        await _dbContext.SaveChangesAsync();
        return Ok();
    }

    [EnableRateLimiting(nameof(RateLimiters.Slow))]
    [HttpPatch("retract-invite")]
    public async Task<IActionResult> RetractInvite([FromBody] string invitedId)
    {
        User? addressee = await _dbContext.Users.FirstOrDefaultAsync(user => user.Id == invitedId);
        if (addressee == null)
            return NotFound("No such user exists");

        User? user = await GetCurrentUser();
        if (user == null)
            // will swap to NotFound once done
            return Unauthorized();

        GroupInvite? existingInvite = await _dbContext.GroupInvites.FirstOrDefaultAsync(oldInvite =>
            oldInvite.UserId == invitedId && oldInvite.GroupId == user.GroupId);
        if (existingInvite == null)
            return NotFound();

        // expired or not, remove it from db
        _dbContext.Remove(existingInvite);
        await _dbContext.SaveChangesAsync();

        if (existingInvite.IsExpired())
            return NotFound();
        return Ok();
    }

    [HttpGet("my-invites")]
    public async Task<IActionResult> GetMyInvites()
    {
        User? user = await GetCurrentUser();
        if (user == null)
            return Unauthorized();

        List<InviteDisplayDTO> invites = user
            .Invites.Select(invite => new InviteDisplayDTO(invite)).ToList();
        return Ok(invites);
    }

    [HttpGet("sent-invites")]
    public async Task<IActionResult> GetSentInvites()
    {
        User? user = await GetCurrentUser();
        if (user == null)
            return Unauthorized();
        if (user.Group == null)
            return NotFound();

        List<InviteDisplayDTO> invites = user.Group.Invites
            .Select(invite => new InviteDisplayDTO(invite))
            .ToList();
        return Ok(invites);
    }

    [EnableRateLimiting(nameof(RateLimiters.Slow))]
    [HttpPost("accept-invite")]
    public async Task<IActionResult> AcceptInvite([FromBody] NewInviteDTO invite)
    {
        User? user = await GetCurrentUser();
        if (user == null || user.Id != invite.UserId)
            // will swap to NotFound once done
            return Unauthorized();

        if (user.Group != null)
            return BadRequest("Cannot join a group while part of another");

        GroupInvite? foundInvite = await _dbContext.GroupInvites
            .Include(i => i.Group)
            .FirstOrDefaultAsync(foundInvite =>
                foundInvite.UserId == invite.UserId && foundInvite.GroupId == invite.GroupId);
        if (foundInvite == null)
            return NotFound();

        _dbContext.Remove(foundInvite);
        if (foundInvite.IsExpired())
            return NotFound();

        Group group = foundInvite.Group;
        group.Members.Add(user);
        user.Group = group;
        await _dbContext.SaveChangesAsync();
        return Ok();
    }

    [EnableRateLimiting(nameof(RateLimiters.Slow))]
    [HttpPost("deny-invite")]
    public async Task<IActionResult> DenyInvite([FromBody] NewInviteDTO invite)
    {
        User? user = await GetCurrentUser();
        if (user == null || user.Id != invite.UserId)
            // will swap to NotFound once done
            return Unauthorized();

        GroupInvite? foundInvite = await _dbContext.GroupInvites.FirstOrDefaultAsync(foundInvite =>
            foundInvite.UserId == invite.UserId && foundInvite.GroupId == invite.GroupId);
        if (foundInvite == null)
            return NotFound();

        _dbContext.Remove(foundInvite);
        await _dbContext.SaveChangesAsync();

        if (foundInvite.IsExpired())
            return NotFound();
        return Ok();
    }

    [EnableRateLimiting(nameof(RateLimiters.Slow))]
    [HttpPost("leave")]
    public async Task<IActionResult> LeaveGroup()
    {
        User? user = await GetCurrentUser();
        if (user == null)
            // will swap to NotFound once done
            return Unauthorized();

        if (user.Group == null)
            return BadRequest("You are not in a group right now");

        Group group = user.Group;
        group.Members.Remove(user);

        if (group.Members.Count == 0)
            _dbContext.Remove(group);
        else
        {
            if (group.Owner == user)
            {
                group.Owner = group.Members.OrderBy(member => member.JoinTime).First();
            }
        }

        // TODO: fix crash that happens here
        await _dbContext.SaveChangesAsync();
        return Ok();
    }

    [EnableRateLimiting(nameof(RateLimiters.Slow))]
    [HttpGet("is-invited/{userId}")]
    public async Task<IActionResult> IsInvited(string userId)
    {
        User? inviter = await GetCurrentUser();
        if (inviter == null || inviter.GroupId == null)
            return Unauthorized();
        Group? group = inviter.Group;
        if (group == null)
            throw new Exception("GroupId was not null but Group was????");
        return Ok(group.Invites.Any(invite => invite.UserId == userId));
    }

    private async Task<User?> GetCurrentUser()
    {
        return await _userManager.GetUserAsync(User);
    }
}
