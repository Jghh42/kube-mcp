using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using KubeMcp.Audit;
using KubeMcp.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol.Client;

namespace KubeMcp.Tests;

public sealed class AuthenticationTests
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private const string ApiKey = "stage-five-test-api-key-32-bytes-minimum";

    [Fact]
    public async Task ApiKeyModeProtectsOnlyMcpEndpoint()
    {
        var auditSink = new CapturingAuditSink();
        await using var factory = CreateFactory(new Dictionary<string, string?>
        {
            ["KubeMcp:Authentication:Mode"] = "ApiKey",
            ["KubeMcp:Authentication:ApiKey"] = ApiKey
        }, services => services.AddSingleton<IAuditSink>(auditSink));
        using var client = factory.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/healthz")).StatusCode);
        using (var missing = await client.PostAsync("/mcp", JsonContent.Create(new { })))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
            Assert.Equal("Bearer", Assert.Single(missing.Headers.WwwAuthenticate).Scheme);
        }

        var authenticationDenial = await auditSink.WaitForAsync(AuditCategories.AuthenticationDenied);
        Assert.Equal(AuditEventType.McpAccessDenied, authenticationDenial.EventType);
        Assert.Null(authenticationDenial.Operation);
        Assert.Null(authenticationDenial.Resource);
        Assert.Null(authenticationDenial.Namespace);
        Assert.Null(authenticationDenial.Name);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            "incorrect-api-key-that-is-long-enough");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/mcp", JsonContent.Create(new { }))).StatusCode);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("ApiKey", ApiKey);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/mcp", JsonContent.Create(new { }))).StatusCode);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ApiKey);
        await AssertSingleToolAsync(client);
    }

    [Fact]
    public async Task OAuthModeValidatesSignatureIssuerAudienceLifetimeScopeAndRole()
    {
        await using var oidc = await TestOidcServer.StartAsync();
        var auditSink = new CapturingAuditSink();
        await using var factory = CreateFactory(new Dictionary<string, string?>
        {
            ["KubeMcp:Authentication:Mode"] = "OAuthClientCredentials",
            ["KubeMcp:Authentication:OAuth:Authority"] = oidc.Authority,
            ["KubeMcp:Authentication:OAuth:Audience"] = "k-mcp",
            ["KubeMcp:Authentication:OAuth:RequiredScopes:0"] = "k-mcp:read",
            ["KubeMcp:Authentication:OAuth:RequiredRoles:0"] = "k-mcp:read",
            ["KubeMcp:Authentication:OAuth:RequireHttpsMetadata"] = "false",
            ["KubeMcp:Authentication:OAuth:ClockSkewSeconds"] = "0"
        }, services => services.AddSingleton<IAuditSink>(auditSink));
        using var client = factory.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/readyz")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(client));

        var valid = oidc.IssueToken("k-mcp", [
            new Claim("scope", "k-mcp:read"),
            new Claim("roles", "k-mcp:read")
        ]);
        SetBearer(client, valid);
        await AssertSingleToolAsync(client);

        SetBearer(client, oidc.IssueToken("other-api", [
            new Claim("scope", "k-mcp:read"),
            new Claim("roles", "k-mcp:read")
        ]));
        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(client));

        SetBearer(client, oidc.IssueToken("k-mcp", [new Claim("roles", "k-mcp:read")]));
        Assert.Equal(HttpStatusCode.Forbidden, await PostMcpAsync(client));
        var authorizationDenial = await auditSink.WaitForAsync(AuditCategories.AuthorizationDenied);
        Assert.Equal("test-client", authorizationDenial.ClientIdentity);
        Assert.Null(authorizationDenial.Resource);

        SetBearer(client, oidc.IssueToken("k-mcp", [new Claim("scope", "k-mcp:read")]));
        Assert.Equal(HttpStatusCode.Forbidden, await PostMcpAsync(client));

        SetBearer(client, oidc.IssueToken(
            "k-mcp",
            [new Claim("scope", "k-mcp:read"), new Claim("roles", "k-mcp:read")],
            expires: DateTime.UtcNow.AddMinutes(-1)));
        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(client));

        SetBearer(client, oidc.IssueToken(
            "k-mcp",
            [new Claim("scope", "k-mcp:read"), new Claim("roles", "k-mcp:read")],
            issuer: "https://wrong-issuer.example"));
        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(client));
    }

    [Fact]
    public void OAuthRoleEvaluatorSupportsKeycloakRealmAndClientRoles()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim("realm_access", "{\"roles\":[\"realm-reader\"]}"),
            new Claim("resource_access", "{\"k-mcp\":{\"roles\":[\"client-reader\"]}}")
        ]));

        Assert.True(OAuthClaimEvaluator.HasAllRoles(
            principal,
            ["realm-reader", "client-reader"],
            "k-mcp"));
        Assert.False(OAuthClaimEvaluator.HasAllRoles(principal, ["missing-role"], "k-mcp"));
        Assert.False(OAuthClaimEvaluator.HasAllRoles(principal, ["client-reader"], "other-api"));
    }

    private static WebApplicationFactory<Program> CreateFactory(
        IReadOnlyDictionary<string, string?> settings,
        Action<IServiceCollection>? configureServices = null) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            foreach (var setting in settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            if (configureServices is not null)
            {
                builder.ConfigureServices(configureServices);
            }
        });

    private static async Task AssertSingleToolAsync(HttpClient client)
    {
        await using var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(client.BaseAddress!, "/mcp"),
                Name = "authentication-test"
            },
            client,
            loggerFactory: null,
            ownsHttpClient: false);
        await using var mcpClient = await McpClient.CreateAsync(transport);

        Assert.Equal("k8s_get", Assert.Single(await mcpClient.ListToolsAsync()).Name);
    }

    private static async Task<HttpStatusCode> PostMcpAsync(HttpClient client)
    {
        using var response = await client.PostAsync("/mcp", JsonContent.Create(new { }));
        return response.StatusCode;
    }

    private static void SetBearer(HttpClient client, string token) =>
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

    private sealed class CapturingAuditSink : IAuditSink
    {
        private readonly object sync = new();
        private readonly List<AuditRecord> records = [];

        public ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken)
        {
            lock (sync)
            {
                records.Add(record);
                Monitor.PulseAll(sync);
            }

            return ValueTask.CompletedTask;
        }

        public async Task<AuditRecord> WaitForAsync(string category)
        {
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (DateTime.UtcNow < deadline)
            {
                lock (sync)
                {
                    var found = records.FirstOrDefault(record => record.Category == category);
                    if (found is not null)
                    {
                        return found;
                    }
                }

                await Task.Delay(10);
            }

            throw new TimeoutException($"Audit category {category} was not delivered.");
        }
    }

    private sealed class TestOidcServer : IAsyncDisposable
    {
        private readonly RSA rsa;
        private readonly RsaSecurityKey signingKey;
        private readonly WebApplication app;

        private TestOidcServer(RSA rsa, RsaSecurityKey signingKey, WebApplication app)
        {
            this.rsa = rsa;
            this.signingKey = signingKey;
            this.app = app;
        }

        public string Authority { get; private set; } = string.Empty;

        public static async Task<TestOidcServer> StartAsync()
        {
            var rsa = RSA.Create(2048);
            var signingKey = new RsaSecurityKey(rsa) { KeyId = Guid.NewGuid().ToString("N") };
            var builder = WebApplication.CreateSlimBuilder();
            builder.WebHost.ConfigureKestrel(options =>
                options.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = HttpProtocols.Http1));
            var app = builder.Build();
            var server = new TestOidcServer(rsa, signingKey, app);

            app.MapGet("/.well-known/openid-configuration", context =>
            {
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsync(JsonSerializer.Serialize(new
                {
                    issuer = server.Authority,
                    jwks_uri = $"{server.Authority}/jwks",
                    token_endpoint = $"{server.Authority}/token"
                }));
            });
            app.MapGet("/jwks", context =>
            {
                var parameters = rsa.ExportParameters(false);
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsync(JsonSerializer.Serialize(new
                {
                    keys = new[]
                    {
                        new
                        {
                            kty = "RSA",
                            use = "sig",
                            alg = SecurityAlgorithms.RsaSha256,
                            kid = signingKey.KeyId,
                            n = Base64UrlEncoder.Encode(parameters.Modulus),
                            e = Base64UrlEncoder.Encode(parameters.Exponent)
                        }
                    }
                }));
            });

            await app.StartAsync();
            server.Authority = app.Urls.Single().TrimEnd('/');
            return server;
        }

        public string IssueToken(
            string audience,
            IEnumerable<Claim> claims,
            DateTime? expires = null,
            string? issuer = null)
        {
            var now = DateTime.UtcNow;
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer ?? Authority,
                Audience = audience,
                Subject = new ClaimsIdentity(claims.Append(new Claim("client_id", "test-client"))),
                IssuedAt = now.AddMinutes(-1),
                NotBefore = now.AddMinutes(-1),
                Expires = expires ?? now.AddMinutes(5),
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256)
            };

            return new JsonWebTokenHandler().CreateToken(descriptor);
        }

        public async ValueTask DisposeAsync()
        {
            await app.DisposeAsync();
            rsa.Dispose();
        }
    }
}
