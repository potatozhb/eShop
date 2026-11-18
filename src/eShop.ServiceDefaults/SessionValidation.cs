using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace eShop.ServiceDefaults;

public record SessionCredential(string SubjectId, string Version);

public sealed class SessionValidationClient(HttpClient client)
{
    public const string VersionClaim = "session_version";

    public async Task<bool> IsCurrentAsync(ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        var subject = principal.FindFirstValue("sub") ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);
        var version = principal.FindFirstValue(VersionClaim);
        if (string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(version))
        {
            return false;
        }

        // No positive cache: a disconnected client cannot extend the revocation window.
        try
        {
            using var response = await client.PostAsJsonAsync("account/session/validate",
                new SessionCredential(subject, version), cancellationToken);
            return response.StatusCode == HttpStatusCode.NoContent;
        }
        catch (HttpRequestException)
        {
            return false;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    public async Task<bool> RevokeAsync(ClaimsPrincipal principal, string clientId, string clientSecret,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "account/sessions/revoke");
        // Confidential WebApp authenticates on the back channel; the subject and version
        // come from its validated cookie, never from the posted browser form.
        request.Headers.Authorization = new("Basic", Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(clientSecret)}")));
        request.Content = JsonContent.Create(new SessionCredential(
            principal.FindFirstValue("sub") ?? principal.FindFirstValue(ClaimTypes.NameIdentifier)!,
            principal.FindFirstValue(VersionClaim)!));
        using var response = await client.SendAsync(request, cancellationToken);
        return response.StatusCode == HttpStatusCode.NoContent;
    }
}

public static class SessionValidationExtensions
{
    public static void AddSessionValidation(this IServiceCollection services, string identityUrl)
    {
#pragma warning disable EXTEXP0001 // Authentication checks must not retry beyond their two-second deadline.
        services.AddHttpClient<SessionValidationClient>(client =>
        {
            client.BaseAddress = new Uri(identityUrl.TrimEnd('/') + "/");
            client.Timeout = TimeSpan.FromSeconds(2);
        }).RemoveAllResilienceHandlers();
#pragma warning restore EXTEXP0001
    }

    public static async Task ValidateSessionAsync(CookieValidatePrincipalContext context)
    {
        var validator = context.HttpContext.RequestServices.GetRequiredService<SessionValidationClient>();
        if (context.Principal is null ||
            !await validator.IsCurrentAsync(context.Principal, context.HttpContext.RequestAborted))
        {
            context.RejectPrincipal();
        }
    }
}
