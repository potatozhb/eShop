using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.IdentityModel.Tokens.Jwt;
using eShop.ServiceDefaults;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace eShop.Authentication.FunctionalTests;

[TestClass]
[DoNotParallelize]
public sealed class SignOutEverywhereTests
{
    private AuthenticationFixture _fixture = null!;
    public TestContext TestContext { get; set; } = null!;

    [TestInitialize]
    public async Task InitializeAsync()
    {
        _fixture = new AuthenticationFixture();
        await _fixture.InitializeAsync();
    }

    [TestCleanup]
    public async Task CleanupAsync() => await _fixture.DisposeAsync();

    [TestMethod]
    public async Task ActionRequiresAuthenticationAndValidAntiforgery()
    {
        using var anonymous = _fixture.NewBrowser();
        using var anonymousResponse = await anonymous.RevokeAsync(csrf: false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);

        using var first = _fixture.NewBrowser();
        using var second = _fixture.NewBrowser();
        var tokens = await first.LoginAsync();
        await second.LoginAsync();
        using var missingCsrf = await first.RevokeAsync(csrf: false);
        Assert.AreEqual(HttpStatusCode.BadRequest, missingCsrf.StatusCode);
        using var invalidCsrf = await first.Client.PostAsync("/account/signout-everywhere",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = "invalid" }), TestContext.CancellationToken);
        Assert.AreEqual(HttpStatusCode.BadRequest, invalidCsrf.StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, (await first.Client.GetAsync("/protected", TestContext.CancellationToken)).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, (await second.Client.GetAsync("/protected", TestContext.CancellationToken)).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, await _fixture.ApiStatusAsync("orders", tokens.AccessToken));
        using var refreshed = await _fixture.RefreshAsync("webapp", tokens.RefreshToken);
        Assert.IsFalse(refreshed.RootElement.TryGetProperty("error", out _));
    }

    [TestMethod]
    public async Task RevokesCookiesAccessTokensRotatedRefreshTokensAndIdentitySessionsAcrossInstances()
    {
        using var first = _fixture.NewBrowser(0);
        using var second = _fixture.NewBrowser(0);
        using var otherClient = _fixture.NewBrowser(0);
        using var unaffected = _fixture.NewBrowser(0);
        var firstTokens = await first.LoginAsync();
        var secondTokens = await second.LoginAsync();
        var clientTokens = await otherClient.LoginAsync(app: "webhooksclient");
        var unaffectedTokens = await unaffected.LoginAsync("bob");
        using var rotatedFirst = await _fixture.RefreshAsync("webapp", firstTokens.RefreshToken, 1);
        using var rotatedClient = await _fixture.RefreshAsync("webhooksclient", clientTokens.RefreshToken, 1);
        var firstReplacement = rotatedFirst.RootElement.GetProperty("refresh_token").GetString()!;
        var clientReplacement = rotatedClient.RootElement.GetProperty("refresh_token").GetString()!;
        Assert.AreNotEqual(firstTokens.RefreshToken, firstReplacement);
        Assert.AreNotEqual(clientTokens.RefreshToken, clientReplacement);
        var oldAccessTokens = new[]
        {
            firstTokens.AccessToken, clientTokens.AccessToken,
            rotatedFirst.RootElement.GetProperty("access_token").GetString()!,
            rotatedClient.RootElement.GetProperty("access_token").GetString()!
        };
        foreach (var token in oldAccessTokens)
            Assert.IsTrue(new JwtSecurityTokenHandler().ReadJwtToken(token).ValidTo > DateTime.UtcNow.AddMinutes(1));
        foreach (var api in new[] { "orders", "webhooks", "basket" })
            foreach (var token in oldAccessTokens)
                Assert.AreEqual(HttpStatusCode.OK, await _fixture.ApiStatusAsync(api, token), api);

        var oldCookie = first.Cookie("webapp");
        var oldIdentityCookie = second.Cookie("identity");
        // Login and issue grants on instance zero, revoke on instance one.
        first.Instance = 1;
        using var response = await first.RevokeAsync(otherSubject: "bob");
        Assert.AreEqual(HttpStatusCode.NoContent, response.StatusCode);
        Assert.IsEmpty(await response.Content.ReadAsByteArrayAsync(TestContext.CancellationToken));
        var elapsed = Stopwatch.StartNew();

        // Replay the actual pre-action cookie, including the calling browser's deleted cookie.
        first.RestoreCookie("webapp", oldCookie);
        foreach (var instance in new[] { 0, 1 })
        {
            second.RestoreCookie("identity", oldIdentityCookie);
            first.Instance = second.Instance = otherClient.Instance = instance;
            Assert.AreEqual(HttpStatusCode.Redirect, (await first.Client.GetAsync("/protected", TestContext.CancellationToken)).StatusCode);
            using var protectedPage = await second.Client.GetAsync("/protected", TestContext.CancellationToken);
            Assert.AreEqual(HttpStatusCode.Redirect, protectedPage.StatusCode);
            Assert.AreEqual("/connect/authorize", protectedPage.Headers.Location!.AbsolutePath);
            Assert.AreEqual(HttpStatusCode.Redirect,
                (await otherClient.Client.GetAsync("https://webhooksclient/protected", TestContext.CancellationToken)).StatusCode);
            foreach (var api in new[] { "orders", "webhooks", "basket" })
                foreach (var token in oldAccessTokens)
                    Assert.AreEqual(HttpStatusCode.Unauthorized, await _fixture.ApiStatusAsync(api, token, instance), api);
            foreach (var (client, refresh) in new[]
            {
                ("webapp", firstTokens.RefreshToken), ("webapp", secondTokens.RefreshToken),
                ("webapp", firstReplacement), ("webhooksclient", clientTokens.RefreshToken),
                ("webhooksclient", clientReplacement)
            })
            {
                using var rejected = await _fixture.RefreshAsync(client, refresh, instance);
                Assert.AreEqual("invalid_grant", rejected.RootElement.GetProperty("error").GetString());
            }

            // A stale IdP cookie must not silently mint new credentials.
            var authorize = "https://identity/connect/authorize?client_id=webapp&response_type=code" +
                "&scope=openid&redirect_uri=https%3A%2F%2Fwebapp%2Fsignin-oidc&prompt=none&state=old";
            using var silent = await second.Client.GetAsync(authorize, TestContext.CancellationToken);
            Assert.AreEqual(HttpStatusCode.Redirect, silent.StatusCode);
            Assert.AreEqual("login_required", QueryHelpers.ParseQuery(silent.Headers.Location!.Query)["error"].ToString());
        }
        Assert.IsTrue(elapsed.Elapsed < TimeSpan.FromSeconds(5), $"Revocation took {elapsed.Elapsed}.");

        foreach (var instance in new[] { 0, 1 })
        {
            unaffected.Instance = instance;
            Assert.AreEqual(HttpStatusCode.OK, (await unaffected.Client.GetAsync("/protected", TestContext.CancellationToken)).StatusCode);
            foreach (var api in new[] { "orders", "webhooks", "basket" })
                Assert.AreEqual(HttpStatusCode.OK, await _fixture.ApiStatusAsync(api, unaffectedTokens.AccessToken, instance));
        }
        using var unaffectedRefresh = await _fixture.RefreshAsync("webapp", unaffectedTokens.RefreshToken);
        Assert.IsFalse(unaffectedRefresh.RootElement.TryGetProperty("error", out _));

        using var freshBrowser = _fixture.NewBrowser(1);
        var fresh = await freshBrowser.LoginAsync();
        Assert.AreEqual(HttpStatusCode.OK, (await freshBrowser.Client.GetAsync("/protected", TestContext.CancellationToken)).StatusCode);
        foreach (var api in new[] { "orders", "webhooks", "basket" })
            Assert.AreEqual(HttpStatusCode.OK, await _fixture.ApiStatusAsync(api, fresh.AccessToken, 0));
        using var freshRefresh = await _fixture.RefreshAsync("webapp", fresh.RefreshToken, 0);
        Assert.IsFalse(freshRefresh.RootElement.TryGetProperty("error", out _));
    }

    [TestMethod]
    public async Task DisconnectedClientCannotReuseCredentialsAfterDeadline()
    {
        using var caller = _fixture.NewBrowser();
        using var disconnected = _fixture.NewBrowser();
        await caller.LoginAsync();
        var old = await disconnected.LoginAsync();
        using var response = await caller.RevokeAsync();
        Assert.AreEqual(HttpStatusCode.NoContent, response.StatusCode);
        // No requests or notifications to the disconnected client during the deadline.
        await Task.Delay(TimeSpan.FromMilliseconds(5100), TestContext.CancellationToken);
        disconnected.Instance = 1;
        Assert.AreEqual(HttpStatusCode.Redirect, (await disconnected.Client.GetAsync("/protected", TestContext.CancellationToken)).StatusCode);
        foreach (var api in new[] { "orders", "webhooks", "basket" })
            Assert.AreEqual(HttpStatusCode.Unauthorized, await _fixture.ApiStatusAsync(api, old.AccessToken, 1));
        using var refresh = await _fixture.RefreshAsync("webapp", old.RefreshToken, 1);
        Assert.AreEqual("invalid_grant", refresh.RootElement.GetProperty("error").GetString());
    }

    [TestMethod]
    public async Task ConcurrentAcceptedActionsAreIdempotentAndOldRetriesCannotRevokeNewLogin()
    {
        using var browser = _fixture.NewBrowser();
        using var concurrent = _fixture.NewBrowser(1);
        var old = await browser.LoginAsync();
        await concurrent.LoginAsync();
        var oldCookie = browser.Cookie("webapp");
        // Hold both requests after authentication, then let both perform the action.
        _fixture.SynchronizeNextRevocations(2);
        var responses = await Task.WhenAll(browser.RevokeAsync(), concurrent.RevokeAsync());
        foreach (var response in responses)
        {
            using (response) Assert.AreEqual(HttpStatusCode.NoContent, response.StatusCode);
        }
        browser.RestoreCookie("webapp", oldCookie);
        using var repeated = await browser.RevokeAsync(csrf: false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, repeated.StatusCode);
        using var recovery = _fixture.NewBrowser();
        var fresh = await recovery.LoginAsync();
        // A delayed back-channel retry is idempotent and cannot revoke the fresh login.
        var version = new JwtSecurityTokenHandler().ReadJwtToken(old.AccessToken).Claims
            .Single(claim => claim.Type == SessionValidationClient.VersionClaim).Value;
        using var retry = new HttpRequestMessage(HttpMethod.Post, "https://identity/account/sessions/revoke")
        {
            Content = JsonContent.Create(new SessionCredential("alice", version))
        };
        retry.Headers.Authorization = new("Basic", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("webapp:secret")));
        using var retryResponse = await browser.Client.SendAsync(retry, TestContext.CancellationToken);
        Assert.AreEqual(HttpStatusCode.NoContent, retryResponse.StatusCode);
        using var replay = await browser.RevokeAsync(csrf: false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, (await recovery.Client.GetAsync("/protected", TestContext.CancellationToken)).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, await _fixture.ApiStatusAsync("orders", fresh.AccessToken));
    }

    [TestMethod]
    public async Task OrdinarySignOutLeavesIndependentSessionAndTokensWorking()
    {
        using var first = _fixture.NewBrowser();
        using var second = _fixture.NewBrowser();
        await first.LoginAsync();
        var secondTokens = await second.LoginAsync();
        using var logout = await first.Client.PostAsync("/ordinary-signout", null, TestContext.CancellationToken);
        Assert.AreEqual(HttpStatusCode.Redirect, logout.StatusCode);
        using var completed = await first.FollowAsync(logout.Headers.Location!);
        Assert.AreEqual(HttpStatusCode.Redirect, (await first.Client.GetAsync("/protected", TestContext.CancellationToken)).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, (await second.Client.GetAsync("/protected", TestContext.CancellationToken)).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, await _fixture.ApiStatusAsync("orders", secondTokens.AccessToken));
        using var refresh = await _fixture.RefreshAsync("webapp", secondTokens.RefreshToken);
        Assert.IsFalse(refresh.RootElement.TryGetProperty("error", out _));
    }
}
