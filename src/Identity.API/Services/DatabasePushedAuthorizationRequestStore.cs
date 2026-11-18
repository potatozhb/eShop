namespace eShop.Identity.API.Services;

public sealed class DatabasePushedAuthorizationRequestStore(ApplicationDbContext database) : IPushedAuthorizationRequestStore
{
    public async Task StoreAsync(PushedAuthorizationRequest request)
    {
        database.PushedAuthorizationRequests.Add(request);
        await database.SaveChangesAsync();
    }

    public Task<PushedAuthorizationRequest> GetByHashAsync(string hash) =>
        database.PushedAuthorizationRequests.AsNoTracking().SingleOrDefaultAsync(request => request.ReferenceValueHash == hash);

    public async Task ConsumeByHashAsync(string hash) =>
        await database.PushedAuthorizationRequests.Where(request => request.ReferenceValueHash == hash).ExecuteDeleteAsync();
}
