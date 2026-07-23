using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Grocery_Server.Services;

public class CleanupService
{
    private readonly GroceryDbContext _dbContext;
    private readonly ImageStorageService _imageStorageService;

    public CleanupService(
        [FromServices] GroceryDbContext dbContext,
        [FromServices] ImageStorageService imageStorageService
    )
    {
        _dbContext = dbContext;
        _imageStorageService = imageStorageService;
    }

    /// <summary>
    /// Will start a periodic timer which keeps calling the cleanup cycle.
    /// </summary>
    /// <returns></returns>
    public async Task Schedule(CancellationToken cancellationToken)
    {
        using PeriodicTimer timer = new(TimeSpan.FromMinutes(2));
        while (
            !cancellationToken.IsCancellationRequested
            && await timer.WaitForNextTickAsync(cancellationToken)
        )
        {
            await CleanupCycle();
        }
    }

    public async Task CleanupCycle()
    {
        // Cleanup expired group invites, old grocery lists
        _dbContext.Database.Migrate();
        _dbContext.RemoveRange(
            _dbContext.GroupInvites.Where(invite => invite.ExpirationTime < DateTime.UtcNow)
        );
        _dbContext.RemoveRange(
            _dbContext.GroceryLists.Where(list => list.CreationTime < DateTime.UtcNow.AddDays(-365))
        );

        await _dbContext.SaveChangesAsync();

        // Cleanup pictures of deleted accounts
        IQueryable<Models.RecipePicture> toRemoveRecipePictures = _dbContext.RecipePictures.Where(
            rp => rp.RecipeId == null
        );
        IQueryable<Models.ProfilePicture> toRemoveProfilePictures =
            _dbContext.ProfilePictures.Where(pfp => pfp.UserId == null);

        IEnumerable<string> rpFileNames = toRemoveRecipePictures.Select(rp => rp.FileName);
        IEnumerable<string> pfpFileNames = toRemoveProfilePictures.Select(pfp => pfp.FileName);

        foreach (var rpFile in rpFileNames)
            _imageStorageService.DeleteImage(rpFile);
        foreach (var pfpFile in pfpFileNames)
            _imageStorageService.DeleteImage(pfpFile);

        _dbContext.RemoveRange(toRemoveProfilePictures);
        _dbContext.RemoveRange(toRemoveRecipePictures);
        await _dbContext.SaveChangesAsync();
    }
}
