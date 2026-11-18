namespace eShop.Identity.API.Controllers;

[ApiController]
public sealed class SessionController(SessionVersionService sessions, IClientSecretValidator clients) : ControllerBase
{
    // A validity check reveals no stamp or personal data. Only signed principals at the caller
    // may use this result to grant access. Responses must never be cached.
    [HttpPost("/account/session/validate")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> Validate(SessionCredential credential, CancellationToken cancellationToken)
    {
        return await sessions.IsCurrentAsync(credential.SubjectId, credential.Version, cancellationToken)
            ? NoContent() : Unauthorized();
    }

    [HttpPost("/account/sessions/revoke")]
    public async Task<IActionResult> Revoke(SessionCredential credential, CancellationToken cancellationToken)
    {
        // This endpoint is a confidential-client back channel, not a browser action.
        // The WebApp derives the subject from its authenticated, CSRF-protected request.
        var result = await clients.ValidateAsync(HttpContext);
        if (result.IsError || result.Client.ClientId != "webapp")
        {
            return Unauthorized();
        }

        await sessions.RevokeAsync(credential.SubjectId, credential.Version, cancellationToken);
        return NoContent();
    }
}
