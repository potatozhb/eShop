namespace eShop.Identity.API.Data;

/// <remarks>
/// Add migrations using the following command inside the 'Identity.API' project directory:
///
/// dotnet ef migrations add [migration-name]
/// </remarks>
public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public DbSet<PersistedGrant> PersistedGrants => Set<PersistedGrant>();
    public DbSet<AuthenticationSigningKey> AuthenticationSigningKeys => Set<AuthenticationSigningKey>();
    public DbSet<PushedAuthorizationRequest> PushedAuthorizationRequests => Set<PushedAuthorizationRequest>();

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<PersistedGrant>(entity =>
        {
            entity.ToTable("PersistedGrants");
            entity.HasKey(grant => grant.Key);
            entity.HasIndex(grant => new { grant.SubjectId, grant.ClientId, grant.Type });
        });
        builder.Entity<AuthenticationSigningKey>().ToTable("AuthenticationSigningKeys");
        builder.Entity<PushedAuthorizationRequest>(entity =>
        {
            entity.ToTable("PushedAuthorizationRequests");
            entity.HasKey(request => request.ReferenceValueHash);
        });
        // Customize the ASP.NET Identity model and override the defaults if needed.
        // For example, you can rename the ASP.NET Identity table names and more.
        // Add your customizations after calling base.OnModelCreating(builder);
    }
}
