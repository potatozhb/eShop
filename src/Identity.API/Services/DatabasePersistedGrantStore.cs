namespace eShop.Identity.API.Services;

// Authorization codes and refresh-token families must survive process restarts and be usable
// at every instance. Revocation is enforced by the captured session version, not by a bulk
// grant deletion that could race with refresh-token rotation or a new interactive login.
public sealed class DatabasePersistedGrantStore(ApplicationDbContext database) : IPersistedGrantStore
{
    public async Task StoreAsync(PersistedGrant grant)
    {
        var existing = await database.PersistedGrants.FindAsync(grant.Key);
        if (existing is null)
            database.PersistedGrants.Add(grant);
        else
            database.Entry(existing).CurrentValues.SetValues(grant);
        await database.SaveChangesAsync();
    }

    public Task<PersistedGrant> GetAsync(string key) =>
        database.PersistedGrants.AsNoTracking().SingleOrDefaultAsync(grant => grant.Key == key);

    public async Task<IEnumerable<PersistedGrant>> GetAllAsync(PersistedGrantFilter filter) =>
        await Filter(filter).AsNoTracking().ToListAsync();

    public async Task RemoveAsync(string key) =>
        await database.PersistedGrants.Where(grant => grant.Key == key).ExecuteDeleteAsync();

    public async Task RemoveAllAsync(PersistedGrantFilter filter) => await Filter(filter).ExecuteDeleteAsync();

    private IQueryable<PersistedGrant> Filter(PersistedGrantFilter filter)
    {
        filter.Validate();
        var query = database.PersistedGrants.AsQueryable();
        if (filter.SubjectId is not null) query = query.Where(grant => grant.SubjectId == filter.SubjectId);
        if (filter.SessionId is not null) query = query.Where(grant => grant.SessionId == filter.SessionId);
        if (filter.ClientId is not null) query = query.Where(grant => grant.ClientId == filter.ClientId);
        if (filter.ClientIds is not null) query = query.Where(grant => filter.ClientIds.Contains(grant.ClientId));
        if (filter.Type is not null) query = query.Where(grant => grant.Type == filter.Type);
        if (filter.Types is not null) query = query.Where(grant => filter.Types.Contains(grant.Type));
        return query;
    }
}
