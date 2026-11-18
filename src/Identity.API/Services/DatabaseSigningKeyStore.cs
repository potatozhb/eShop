using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.DataProtection;

namespace eShop.Identity.API.Services;

public sealed class AuthenticationSigningKey
{
    public string Id { get; set; }
    public string Key { get; set; }
}

// All instances publish and use the same key. Production deployments should replace this
// sample key store with managed signing credentials and an appropriate rotation policy.
public sealed class DatabaseSigningKeyStore(IServiceScopeFactory scopes, IDataProtectionProvider dataProtection) : ISigningCredentialStore, IValidationKeysStore
{
    private readonly IDataProtector _protector = dataProtection.CreateProtector("eShop.Identity.SigningKey");

    public async Task<SigningCredentials> GetSigningCredentialsAsync()
    {
        using var scope = scopes.CreateScope();
        var database = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var stored = await database.AuthenticationSigningKeys.AsNoTracking().SingleOrDefaultAsync(key => key.Id == "default");
        if (stored is null)
        {
            using var rsa = RSA.Create(2048);
            var key = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa) { KeyId = Guid.NewGuid().ToString("N") });
            database.AuthenticationSigningKeys.Add(new() { Id = "default", Key = _protector.Protect(System.Text.Json.JsonSerializer.Serialize(key)) });
            try
            {
                await database.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                // Another instance may have created the key first; the unique key decides.
                database.ChangeTracker.Clear();
            }
            stored = await database.AuthenticationSigningKeys.AsNoTracking().SingleAsync(key => key.Id == "default");
        }
        return new SigningCredentials(new Microsoft.IdentityModel.Tokens.JsonWebKey(_protector.Unprotect(stored.Key)), SecurityAlgorithms.RsaSha256);
    }

    public async Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync()
    {
        var credentials = await GetSigningCredentialsAsync();
        return [new SecurityKeyInfo { Key = credentials.Key, SigningAlgorithm = credentials.Algorithm }];
    }
}
