namespace eShop.Identity.API.Services;

public static class SessionIdentityExtensions
{
    public static void AddSessionIdentityServices(this IServiceCollection services)
    {
        services.AddScoped<IUserClaimsPrincipalFactory<ApplicationUser>, SessionClaimsPrincipalFactory>();
        services.Configure<SecurityStampValidatorOptions>(options => options.ValidationInterval = TimeSpan.Zero);
        services.AddScoped<SessionVersionService>();
        services.AddScoped<IPersistedGrantStore, DatabasePersistedGrantStore>();
        services.AddScoped<IPushedAuthorizationRequestStore, DatabasePushedAuthorizationRequestStore>();
        services.AddSingleton<DatabaseSigningKeyStore>();
        services.AddSingleton<ISigningCredentialStore>(provider => provider.GetRequiredService<DatabaseSigningKeyStore>());
        services.AddSingleton<IValidationKeysStore>(provider => provider.GetRequiredService<DatabaseSigningKeyStore>());
        services.AddTransient<IProfileService, ProfileService>();
    }
}
