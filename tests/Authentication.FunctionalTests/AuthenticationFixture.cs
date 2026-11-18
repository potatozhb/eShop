extern alias webapp;
extern alias basket;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;
using Duende.IdentityServer;
using Duende.IdentityServer.Services;
using eShop.Identity.API.Configuration;
using eShop.Identity.API.Controllers;
using eShop.Identity.API.Data;
using eShop.Identity.API.Models;
using eShop.Identity.API.Services;
using eShop.Ordering.API.Application.Queries;
using eShop.Ordering.API.Infrastructure.Services;
using eShop.ServiceDefaults;
using MediatR;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;
using Webhooks.API;
using Webhooks.API.Infrastructure;
using Webhooks.API.Services;

namespace eShop.Authentication.FunctionalTests;

// Real cookie handlers, Identity, IdentityServer, authorization-code and refresh grants,
// and production endpoint mappings. Only transports, business repositories, and database
// provider are replaced. Separate hosts share a relational database and key rings.
internal sealed class AuthenticationFixture : IAsyncDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "eshop-auth-" + Guid.NewGuid().ToString("N"));
    private readonly Dictionary<string, List<WebApplication>> _apps = [];
    private readonly List<IDisposable> _transports = [];
    private Func<Task>? _beforeRevocation;
    public const string Password = "Pass_word1!";

    public void SynchronizeNextRevocations(int count)
    {
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var remaining = count;
        _beforeRevocation = async () =>
        {
            if (Interlocked.Decrement(ref remaining) == 0)
            {
                _beforeRevocation = null;
                ready.SetResult();
            }
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
        };
    }

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        await BuildIdentityAsync();
        await BuildIdentityAsync();
        using (var scope = _apps["identity"][0].Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            foreach (var name in new[] { "alice", "bob" })
            {
                var result = await users.CreateAsync(new ApplicationUser
                {
                    Id = name, UserName = name, Email = name + "@test.local", EmailConfirmed = true,
                    Name = name, LastName = "Test", CardNumber = "123456789012", CardHolderName = name,
                    SecurityNumber = "123", Expiration = "12/30", Street = "Street", City = "City",
                    State = "State", Country = "Country", ZipCode = "12345"
                }, Password);
                Assert.IsTrue(result.Succeeded, string.Join(",", result.Errors.Select(error => error.Description)));
            }
        }
        await BuildWebAsync(false);
        await BuildWebAsync(false);
        await BuildWebAsync(true);
        await BuildWebAsync(true);
        foreach (var api in new[] { "orders", "webhooks", "basket" })
        {
            await BuildApiAsync(api);
            await BuildApiAsync(api);
        }
    }

    private WebApplicationBuilder Builder()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development" });
        builder.Logging.ClearProviders();
        builder.WebHost.UseTestServer();
        return builder;
    }

    private async Task RegisterAsync(string name, WebApplication app)
    {
        await app.StartAsync();
        if (!_apps.TryGetValue(name, out var apps)) _apps[name] = apps = [];
        apps.Add(app);
    }

    private void AddKeys(IServiceCollection services, string name) => services.AddDataProtection()
        .SetApplicationName(name).PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(_directory, name + "-keys")));

    private async Task BuildIdentityAsync()
    {
        var builder = Builder();
        builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlite($"Data Source={_directory}/identity.db"));
        builder.Services.AddControllersWithViews().AddApplicationPart(typeof(SessionController).Assembly);
        AddKeys(builder.Services, "identity");
        builder.Services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["WebAppClient"] = "https://webapp", ["WebhooksWebClient"] = "https://webhooksclient",
            ["MauiCallback"] = "https://maui/callback", ["BasketApiClient"] = "https://basket",
            ["OrderingApiClient"] = "https://orders", ["WebhooksApiClient"] = "https://webhooks"
        }).Build();
        var clients = Config.GetClients(config).ToList();
        builder.Services.AddIdentityServer(options =>
        {
            options.IssuerUri = "https://identity";
            options.KeyManagement.Enabled = false;
        }).AddInMemoryIdentityResources(Config.GetResources()).AddInMemoryApiScopes(Config.GetApiScopes())
            .AddInMemoryApiResources(Config.GetApis()).AddInMemoryClients(clients).AddAspNetIdentity<ApplicationUser>();
        builder.Services.AddSessionIdentityServices();
        var app = builder.Build();
        using (var scope = app.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.EnsureCreatedAsync();
        app.UseIdentityServer();
        app.UseAuthorization();
        app.MapControllers();
        app.MapDefaultControllerRoute();
        await RegisterAsync("identity", app);
    }

    private void RouteSessionChecks(IServiceCollection services) => services.AddHttpClient<SessionValidationClient>()
        .ConfigurePrimaryHttpMessageHandler(() => Transport(1));

    private async Task BuildWebAsync(bool webhook)
    {
        var builder = Builder();
        var name = webhook ? "webhooksclient" : "webapp";
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["IdentityUrl"] = "https://identity", ["CallBackUrl"] = "https://" + name
        });
        builder.Services.AddRazorComponents();
        AddKeys(builder.Services, name);
        if (webhook)
            eShop.WebhookClient.Extensions.Extensions.AddAuthenticationServices(builder);
        else
            webapp::Extensions.AddAuthenticationServices(builder);
        RouteSessionChecks(builder.Services);
        builder.Services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
        {
            options.BackchannelHttpHandler = Transport(0);
            options.Scope.Add("offline_access");
            options.Events.OnTicketReceived = async context =>
            {
                Assert.IsNotNull(context.Principal!.FindFirst(SessionValidationClient.VersionClaim),
                    string.Join(", ", context.Principal.Claims.Select(claim => claim.Type + "=" + claim.Value)));
                Assert.IsTrue(await context.HttpContext.RequestServices.GetRequiredService<SessionValidationClient>()
                    .IsCurrentAsync(context.Principal, CancellationToken.None), "New OIDC ticket failed session validation");
            };
        });
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.Use(async (context, next) =>
        {
            if (context.Request.Path == "/account/signout-everywhere" &&
                context.User.Identity?.IsAuthenticated == true && _beforeRevocation is { } before)
                await before();
            await next();
        });
        app.UseAntiforgery();
        webapp::eShop.WebApp.Endpoints.AccountEndpoints.MapAccountEndpoints(app);
        app.MapGet("/protected", () => Results.Text("authenticated")).RequireAuthorization();
        app.MapGet("/", () => Results.Text("home"));
        app.MapGet("/csrf", (HttpContext context, IAntiforgery antiforgery) =>
            Results.Text(antiforgery.GetAndStoreTokens(context).RequestToken!));
        // Retrieve the tokens actually saved by the OIDC callback, without manufacturing any.
        app.MapGet("/tokens", async (HttpContext context, IAuthenticationService _) => Results.Json(new Tokens(
            (await context.GetTokenAsync("access_token"))!, (await context.GetTokenAsync("refresh_token"))!)))
            .RequireAuthorization();
        app.MapPost("/ordinary-signout", async (HttpContext context) =>
        {
            await new webapp::eShop.WebApp.Services.LogOutService().LogOutAsync(context);
        });
        await RegisterAsync(name, app);
    }

    private async Task BuildApiAsync(string name)
    {
        var builder = Builder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Identity:Url"] = "https://identity", ["Identity:Audience"] = name
        });
        builder.AddDefaultAuthentication();
        RouteSessionChecks(builder.Services);
        builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme,
            options => options.BackchannelHttpHandler = Transport(1));
        builder.Services.AddApiVersioning();
        if (name == "orders")
        {
            builder.Services.AddSingleton(Substitute.For<IOrderQueries>());
            builder.Services.AddSingleton(Substitute.For<IMediator>());
            builder.Services.AddSingleton(Substitute.For<IIdentityService>());
        }
        else if (name == "webhooks")
        {
            builder.Services.AddDbContext<WebhooksContext>(options => options.UseSqlite($"Data Source={_directory}/webhooks.db"));
            builder.Services.AddSingleton(Substitute.For<IGrantUrlTesterService>());
        }
        else
        {
            builder.Services.AddGrpc();
            var repository = Substitute.For<basket::eShop.Basket.API.Repositories.IBasketRepository>();
            repository.UpdateBasketAsync(Arg.Any<basket::eShop.Basket.API.Model.CustomerBasket>())
                .Returns(call => call.Arg<basket::eShop.Basket.API.Model.CustomerBasket>());
            builder.Services.AddSingleton(repository);
        }
        var app = builder.Build();
        if (name == "orders")
            app.NewVersionedApi().MapOrdersApiV1().RequireAuthorization();
        else if (name == "webhooks")
        {
            using var scope = app.Services.CreateScope();
            await scope.ServiceProvider.GetRequiredService<WebhooksContext>().Database.EnsureCreatedAsync();
            app.NewVersionedApi().MapWebHooksApiV1().RequireAuthorization();
        }
        else
            app.MapGrpcService<basket::eShop.Basket.API.Grpc.BasketService>().RequireAuthorization();
        await RegisterAsync(name, app);
    }

    private HttpMessageHandler Transport(int instance = 0)
    {
        var handler = new RoutingHandler(this) { Instance = instance };
        _transports.Add(handler);
        return handler;
    }

    public Browser NewBrowser(int instance = 0) => new(this, instance);

    public async Task<JsonDocument> RefreshAsync(string clientId, string token, int instance = 0)
    {
        using var browser = NewBrowser(instance);
        using var response = await browser.Client.PostAsync("https://identity/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = clientId, ["client_secret"] = "secret", ["grant_type"] = "refresh_token", ["refresh_token"] = token
        }));
        var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        if (document.RootElement.TryGetProperty("error", out var error))
        {
            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.AreEqual("invalid_grant", error.GetString());
        }
        else
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, document.RootElement.ToString());
        return document;
    }

    public async Task<HttpStatusCode> ApiStatusAsync(string api, string token, int instance = 0)
    {
        using var browser = NewBrowser(instance);
        using var request = api == "basket"
            ? new HttpRequestMessage(HttpMethod.Post, "https://basket/BasketApi.Basket/UpdateBasket")
            {
                Version = HttpVersion.Version20, Content = new ByteArrayContent([0, 0, 0, 0, 0])
            }
            : new HttpRequestMessage(HttpMethod.Get, api == "orders"
                ? "https://orders/api/orders/cardtypes?api-version=1.0" : "https://webhooks/api/webhooks/?api-version=1.0");
        if (api == "basket") request.Content!.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await browser.Client.SendAsync(request);
        if (api == "basket" && response.StatusCode == HttpStatusCode.OK)
        {
            var status = response.TrailingHeaders.TryGetValues("grpc-status", out var trailers)
                ? trailers.Single() : response.Headers.GetValues("grpc-status").Single();
            Assert.AreEqual("0", status, "The positive control must succeed at the gRPC layer too.");
        }
        return response.StatusCode;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var app in _apps.Values.SelectMany(apps => apps).Reverse()) await app.DisposeAsync();
        foreach (var transport in _transports) transport.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_directory, true);
    }

    private sealed class RoutingHandler(AuthenticationFixture fixture) : HttpMessageHandler
    {
        public int Instance { get; set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var apps = fixture._apps[request.RequestUri!.Host];
            using var invoker = new HttpMessageInvoker(apps[Math.Min(Instance, apps.Count - 1)].GetTestServer().CreateHandler());
            return await invoker.SendAsync(request, cancellationToken);
        }
    }

    public sealed class Browser : IDisposable
    {
        private readonly CookieContainer _cookies = new();
        private readonly CookieHandler _handler;
        public HttpClient Client { get; }
        public int Instance { get => _handler.Instance; set => _handler.Instance = value; }
        internal Browser(AuthenticationFixture fixture, int instance)
        {
            _handler = new CookieHandler(_cookies, fixture) { Instance = instance };
            Client = new HttpClient(_handler) { BaseAddress = new Uri("https://webapp") };
        }

        public string Cookie(string host) => _cookies.GetCookieHeader(new Uri("https://" + host));
        public void RestoreCookie(string host, string cookie) => _cookies.SetCookies(new Uri("https://" + host), cookie.Replace("; ", ", "));

        public async Task<Tokens> LoginAsync(string user = "alice", string app = "webapp")
        {
            using var challenge = await Client.GetAsync("https://" + app + "/protected");
            Assert.AreEqual(HttpStatusCode.Redirect, challenge.StatusCode);
            var authorizeUrl = challenge.Headers.Location!.ToString();
            using var authorize = await Client.GetAsync(authorizeUrl);
            Assert.AreEqual(HttpStatusCode.Redirect, authorize.StatusCode);
            var loginUrl = new Uri(new Uri("https://identity"), authorize.Headers.Location!);
            using var loginPage = await Client.GetAsync(loginUrl);
            var html = await loginPage.Content.ReadAsStringAsync();
            var csrf = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
            Assert.IsFalse(string.IsNullOrEmpty(csrf), html);
            var returnUrl = QueryHelpers.ParseQuery(loginUrl.Query)["ReturnUrl"].ToString();
            using var login = await Client.PostAsync("https://identity/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Username"] = user, ["Password"] = Password, ["ReturnUrl"] = returnUrl,
                ["button"] = "login", ["__RequestVerificationToken"] = WebUtility.HtmlDecode(csrf)
            }));
            Assert.AreEqual(HttpStatusCode.Redirect, login.StatusCode, await login.Content.ReadAsStringAsync());
            using var callback = await FollowAsync(login.Headers.Location!, new Uri("https://identity"));
            Assert.AreEqual(HttpStatusCode.OK, callback.StatusCode, await callback.Content.ReadAsStringAsync());
            return (await Client.GetFromJsonAsync<Tokens>("https://" + app + "/tokens"))!;
        }

        public async Task<HttpResponseMessage> FollowAsync(Uri location, Uri? origin = null)
        {
            var url = location.IsAbsoluteUri ? location : new Uri(origin ?? Client.BaseAddress!, location);
            var response = await Client.GetAsync(url);
            for (var count = 0; count < 12; count++)
            {
                if (response.StatusCode == HttpStatusCode.Redirect)
                {
                    var next = response.Headers.Location!;
                    url = next.IsAbsoluteUri ? next : new Uri(url, next);
                    response.Dispose();
                    response = await Client.GetAsync(url);
                    continue;
                }
                // IdentityServer's default response_mode=form_post uses an auto-submitting
                // HTML form. An HTTP-only browser must submit it just as a real browser does.
                var html = await response.Content.ReadAsStringAsync();
                var form = Regex.Match(html, """<form[^>]*action=['"]([^'"]+)['"]""", RegexOptions.IgnoreCase);
                if (!form.Success || !form.Groups[1].Value.Contains("signin-oidc", StringComparison.Ordinal))
                    return response;
                var fields = Regex.Matches(html, """<input[^>]*name=['"]([^'"]+)['"][^>]*value=['"]([^'"]*)['"]""")
                    .ToDictionary(match => match.Groups[1].Value, match => WebUtility.HtmlDecode(match.Groups[2].Value));
                url = new Uri(WebUtility.HtmlDecode(form.Groups[1].Value));
                response.Dispose();
                response = await Client.PostAsync(url, new FormUrlEncodedContent(fields));
            }
            throw new InvalidOperationException("Too many redirects");
        }

        public async Task<HttpResponseMessage> RevokeAsync(bool csrf = true, string? otherSubject = null)
        {
            var fields = new Dictionary<string, string>();
            if (csrf) fields["__RequestVerificationToken"] = await Client.GetStringAsync("/csrf");
            if (otherSubject is not null) fields["subjectId"] = otherSubject;
            return await Client.PostAsync("/account/signout-everywhere", new FormUrlEncodedContent(fields));
        }

        public void Dispose() => Client.Dispose();
    }

    private sealed class CookieHandler(CookieContainer cookies, AuthenticationFixture fixture) : HttpMessageHandler
    {
        public int Instance { get; set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.Remove("Cookie");
            var cookie = cookies.GetCookieHeader(request.RequestUri!);
            if (cookie.Length > 0) request.Headers.TryAddWithoutValidation("Cookie", cookie);
            using var transport = new HttpMessageInvoker(new RoutingHandler(fixture) { Instance = Instance });
            var response = await transport.SendAsync(request, cancellationToken);
            if (response.Headers.TryGetValues("Set-Cookie", out var values))
                foreach (var value in values) cookies.SetCookies(request.RequestUri!, value);
            return response;
        }
    }

    public sealed record Tokens(string AccessToken, string RefreshToken);
}
