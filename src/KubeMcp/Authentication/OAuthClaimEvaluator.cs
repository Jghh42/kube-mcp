using System.Security.Claims;
using System.Text.Json;

namespace KubeMcp.Authentication;

internal static class OAuthClaimEvaluator
{
    public static bool HasAllScopes(ClaimsPrincipal principal, IEnumerable<string> requiredScopes)
    {
        var granted = principal.Claims
            .Where(claim => claim.Type is "scope" or "scp")
            .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .ToHashSet(StringComparer.Ordinal);

        return requiredScopes.All(granted.Contains);
    }

    public static bool HasAllRoles(
        ClaimsPrincipal principal,
        IEnumerable<string> requiredRoles,
        string resourceClient)
    {
        var granted = principal.Claims
            .Where(claim => claim.Type is "role" or "roles" || claim.Type == ClaimTypes.Role)
            .SelectMany(ClaimValues)
            .ToHashSet(StringComparer.Ordinal);

        AddKeycloakRealmRoles(principal, granted);
        AddKeycloakClientRoles(principal, granted, resourceClient);

        return requiredRoles.All(granted.Contains);
    }

    private static IEnumerable<string> ClaimValues(Claim claim)
    {
        if (claim.Value.StartsWith("[", StringComparison.Ordinal))
        {
            try
            {
                using var document = JsonDocument.Parse(claim.Value);
                if (document.RootElement.ValueKind == JsonValueKind.Array)
                {
                    return document.RootElement
                        .EnumerateArray()
                        .Where(value => value.ValueKind == JsonValueKind.String)
                        .Select(value => value.GetString()!)
                        .ToArray();
                }
            }
            catch (JsonException)
            {
                return [];
            }
        }

        return [claim.Value];
    }

    private static void AddKeycloakRealmRoles(ClaimsPrincipal principal, HashSet<string> granted)
    {
        foreach (var claim in principal.FindAll("realm_access"))
        {
            try
            {
                using var document = JsonDocument.Parse(claim.Value);
                if (document.RootElement.TryGetProperty("roles", out var roles) && roles.ValueKind == JsonValueKind.Array)
                {
                    foreach (var role in roles.EnumerateArray().Where(value => value.ValueKind == JsonValueKind.String))
                    {
                        granted.Add(role.GetString()!);
                    }
                }
            }
            catch (JsonException)
            {
                // A malformed optional role claim grants no roles.
            }
        }
    }

    private static void AddKeycloakClientRoles(
        ClaimsPrincipal principal,
        HashSet<string> granted,
        string resourceClient)
    {
        foreach (var claim in principal.FindAll("resource_access"))
        {
            try
            {
                using var document = JsonDocument.Parse(claim.Value);
                if (document.RootElement.TryGetProperty(resourceClient, out var client) &&
                    client.TryGetProperty("roles", out var roles) &&
                    roles.ValueKind == JsonValueKind.Array)
                {
                    foreach (var role in roles.EnumerateArray().Where(value => value.ValueKind == JsonValueKind.String))
                    {
                        granted.Add(role.GetString()!);
                    }
                }
            }
            catch (InvalidOperationException)
            {
                // A malformed optional role claim grants no roles.
            }
            catch (JsonException)
            {
                // A malformed optional role claim grants no roles.
            }
        }
    }
}
