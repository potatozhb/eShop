using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace eShop.WebApp.Endpoints;

public static class AccountEndpoints
{
    public static void MapAccountEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/account/signout-everywhere", async (HttpContext context,
            IAntiforgery antiforgery, SessionValidationClient sessions, IOptionsMonitor<OpenIdConnectOptions> options) =>
        {
            // Authenticate before checking CSRF so an expired or missing cookie always receives 401.
            if (context.User.Identity?.IsAuthenticated != true)
            {
                return Results.Unauthorized();
            }

            try
            {
                await antiforgery.ValidateRequestAsync(context);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.BadRequest();
            }

            try
            {
                var client = options.Get(OpenIdConnectDefaults.AuthenticationScheme);
                if (!await sessions.RevokeAsync(context.User, client.ClientId!, client.ClientSecret!, context.RequestAborted))
                {
                    return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                }
            }
            catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException)
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }

            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.NoContent();
        });
    }
}
