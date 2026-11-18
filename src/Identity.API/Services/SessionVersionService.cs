using System.Security.Cryptography;
using System.Text;

namespace eShop.Identity.API.Services;

public sealed class SessionVersionService(ApplicationDbContext database)
{
    public static string FromStamp(string stamp) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(stamp)));

    public async Task<bool> IsCurrentAsync(string subject, string version, CancellationToken cancellationToken = default)
    {
        var stamp = await database.Users.AsNoTracking().Where(user => user.Id == subject)
            .Select(user => user.SecurityStamp).SingleOrDefaultAsync(cancellationToken);
        return stamp is not null && FromStamp(stamp) == version;
    }

    public async Task RevokeAsync(string subject, string version, CancellationToken cancellationToken)
    {
        var previousStamp = await database.Users.AsNoTracking().Where(user => user.Id == subject)
            .Select(user => user.SecurityStamp).SingleOrDefaultAsync(cancellationToken);
        if (previousStamp is null || FromStamp(previousStamp) != version)
            return;

        // Compare-and-swap makes overlapping accepted requests idempotent, without letting
        // a retry from an already-revoked generation invalidate a fresh interactive login.
        var stamp = Guid.NewGuid().ToString();
        var concurrencyStamp = Guid.NewGuid().ToString();
        await database.Users.Where(user => user.Id == subject && user.SecurityStamp == previousStamp).ExecuteUpdateAsync(update => update
            .SetProperty(user => user.SecurityStamp, stamp)
            .SetProperty(user => user.ConcurrencyStamp, concurrencyStamp), cancellationToken);
    }
}

public sealed class SessionClaimsPrincipalFactory(
    UserManager<ApplicationUser> users, RoleManager<IdentityRole> roles, IOptions<IdentityOptions> options)
    : UserClaimsPrincipalFactory<ApplicationUser, IdentityRole>(users, roles, options)
{
    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);
        identity.AddClaim(new Claim(SessionValidationClient.VersionClaim,
            SessionVersionService.FromStamp(await UserManager.GetSecurityStampAsync(user))));
        return identity;
    }
}
