# eShop Tests

This directory contains a collection of unit and functional tests for validating the behavior of various components in the eShop application.

`Authentication.FunctionalTests` runs without containers:

```powershell
dotnet test --project tests/Authentication.FunctionalTests/Authentication.FunctionalTests.csproj
```

It uses real ASP.NET cookie, antiforgery and JWT handlers, IdentityServer authorization-code and
rotating refresh-token flows, two HTTP clients with independent cookie jars, two instances of
each service, and the production Ordering, Webhooks and Basket endpoint mappings. SQLite and
shared file key rings replace PostgreSQL and Redis in these tests; business repositories are
substituted. The tests check the five-second revocation deadline, disconnected clients,
simultaneous actions, user isolation, recovery and ordinary sign-out.

Sign out everywhere advances the user's security stamp in the identity database. Cookies and
tokens carry a hash of the stamp captured during interactive login. Every protected HTTP request
checks that generation against Identity.API without caching successful checks; unavailable
validation fails closed after at most two seconds. Interactive circuits also revalidate.
Identity cookies validate the stamp on every request, and IdentityServer checks the captured
generation when validating refresh tokens. Refresh and authorization grants, pushed requests
and signing credentials are shared through the identity database. Signing credentials are
protected with the Identity data-protection key ring. Each web application shares its own
data-protection key ring through Redis, which AppHost now persists in a data volume.

Deploy the identity database migrations and provide the same PostgreSQL and persistent Redis
services to all instances. Existing credentials without a session-version claim require a new
interactive sign-in. The sample database signing-key store should use managed signing
credentials and key rotation in production, as with the previous developer signing credential.

**NOTE:** The other functional test projects use Aspire to spin up containers and require Docker to be running.
