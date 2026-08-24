using System.Net;
using Microsoft.AspNetCore.Builder;

namespace KubeMcp.Configuration;

internal static class ForwardedHeadersConfiguration
{
    // Configures the ASP.NET Core forwarded-headers middleware from application
    // settings. Only the explicitly configured proxies/networks and the loopback
    // address are trusted. Forwarded hosts use the same allowlist as ASP.NET Core
    // host filtering. The middleware never trusts every proxy.
    public static void Apply(
        KubeMcpForwardedHeadersOptions config,
        ForwardedHeadersOptions options,
        string? allowedHosts)
    {
        options.ForwardedHeaders = config.AllowedForwardedHeaders;
        options.ForwardLimit = 1;
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        options.AllowedHosts.Clear();

        foreach (var host in (allowedHosts ?? string.Empty).Split(
                     ';',
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            options.AllowedHosts.Add(host);
        }

        // Loopback is always trusted so local and localhost reverse-proxy
        // topologies work without explicit configuration. This does not trust
        // arbitrary networks or proxies.
        AddLoopback(options.KnownIPNetworks);

        foreach (var proxy in config.KnownProxies ?? [])
        {
            if (IPAddress.TryParse(proxy, out var address))
            {
                options.KnownProxies.Add(address);
            }
        }

        foreach (var network in config.KnownNetworks ?? [])
        {
            if (System.Net.IPNetwork.TryParse(network, out var parsed))
            {
                options.KnownIPNetworks.Add(parsed);
            }
        }
    }

    private static void AddLoopback(ICollection<System.Net.IPNetwork> networks)
    {
        if (System.Net.IPNetwork.TryParse("127.0.0.0/8", out var ipv4Loopback))
        {
            networks.Add(ipv4Loopback);
        }

        if (System.Net.IPNetwork.TryParse("::1/128", out var ipv6Loopback))
        {
            networks.Add(ipv6Loopback);
        }
    }
}
