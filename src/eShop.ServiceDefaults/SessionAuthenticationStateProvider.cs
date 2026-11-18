using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.Extensions.Logging;

namespace eShop.ServiceDefaults;

// Cookie validation runs on HTTP requests; interactive circuits also need revalidation.
public sealed class SessionAuthenticationStateProvider(ILoggerFactory loggerFactory, SessionValidationClient sessions)
    : RevalidatingServerAuthenticationStateProvider(loggerFactory)
{
    protected override TimeSpan RevalidationInterval => TimeSpan.FromMilliseconds(500);

    protected override Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState,
        CancellationToken cancellationToken) => sessions.IsCurrentAsync(authenticationState.User, cancellationToken);
}
