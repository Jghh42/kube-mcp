using System.Text;
using System.Text.Json;
using KubeMcp.CredentialGate;

namespace KubeMcp.Tests;

public sealed class JsonStateChunkerTests
{
    [Fact]
    public void PacksAdjacentSiblingFieldsIntoOneCompleteState()
    {
        var chunks = new JsonStateChunker(4096, 256)
            .Chunk("{\"name\":\"DB_PASSWORD\",\"value\":\"fabricated-secret\"}")
            .ToArray();
        var entries = Entries(Assert.Single(chunks));

        Assert.Contains(entries, entry => entry.Path == "/name" && entry.Value == "DB_PASSWORD");
        Assert.Contains(entries, entry => entry.Path == "/value" && entry.Value == "fabricated-secret");
    }

    [Fact]
    public void OversizedEnvValueSegmentsRetainNameContextAndCompleteCoverage()
    {
        var credential = "token_" + new string('x', 1800);
        var json = JsonSerializer.Serialize(new
        {
            spec = new
            {
                containers = new[]
                {
                    new { env = new[] { new { name = "API_KEY", value = credential } } }
                }
            }
        });
        var chunks = new JsonStateChunker(800, 32).Chunk(json).ToArray();

        Assert.True(chunks.Length > 2);
        Assert.All(chunks, chunk =>
        {
            Assert.True(Encoding.UTF8.GetByteCount(chunk) <= 800);
            using var _ = JsonDocument.Parse(chunk);
        });
        var valueEntries = chunks.SelectMany(Entries)
            .Where(entry => entry.Path.EndsWith("/value", StringComparison.Ordinal))
            .GroupBy(entry => entry.Start)
            .Select(group => group.First())
            .OrderBy(entry => entry.Start)
            .ToArray();
        Assert.NotEmpty(valueEntries);
        Assert.All(valueEntries, entry => Assert.Contains(
            entry.Context,
            context => context.Path.EndsWith("/name", StringComparison.Ordinal) &&
                context.Value == "API_KEY"));
        Assert.Equal(credential, MergeWithOverlap(valueEntries.Select(entry => entry.Value).ToArray(), 32));
    }

    [Fact]
    public void OrdinaryValueRetainsNameAcrossManyFieldsAndChunkBoundaries()
    {
        var fields = new Dictionary<string, object?>
        {
            ["name"] = "DB_PASSWORD"
        };
        for (var index = 0; index < 30; index++)
        {
            fields[$"padding_{index:D2}"] = new string('p', 24);
        }
        const string credential = "123e4567-e89b-12d3-a456-426614174000";
        fields["value"] = credential;

        var chunks = new JsonStateChunker(400, 32)
            .Chunk(JsonSerializer.Serialize(new { env = new[] { fields } })).ToArray();
        var valueChunk = Array.FindIndex(chunks, chunk => Entries(chunk).Any(entry =>
            entry.Path == "/env/0/value" && entry.Value == credential));
        var nameChunk = Array.FindIndex(chunks, chunk => Entries(chunk).Any(entry =>
            entry.Path == "/env/0/name" && entry.Value == "DB_PASSWORD"));
        Assert.True(valueChunk >= 0);
        Assert.True(nameChunk >= 0);
        Assert.NotEqual(nameChunk, valueChunk);
        var valueEntry = Entries(chunks[valueChunk]).Single(entry =>
            entry.Path == "/env/0/value" && entry.Value == credential);
        Assert.Contains(valueEntry.Context, context =>
            context.Path == "/env/0/name" && context.Value == "DB_PASSWORD");
    }

    [Fact]
    public void NestedLocalContextDoesNotDiscardAncestorNameIdentity()
    {
        const string credential = "123e4567-e89b-12d3-a456-426614174000";
        var json = JsonSerializer.Serialize(new
        {
            name = "API_TOKEN",
            wrapper = new
            {
                kind = "credential-holder",
                deep = new { value = credential }
            }
        });

        var valueEntry = new JsonStateChunker(500, 32).Chunk(json)
            .SelectMany(Entries)
            .First(entry => entry.Path.EndsWith("/value", StringComparison.Ordinal));

        Assert.Contains(valueEntry.Context, context =>
            context.Path == "/name" && context.Value == "API_TOKEN");
        Assert.Contains(valueEntry.Context, context =>
            context.Path == "/wrapper/kind" && context.Value == "credential-holder");
    }

    [Fact]
    public void ConsecutiveStatesOverlapAcrossArrayEntryBoundaries()
    {
        var json = JsonSerializer.Serialize(new
        {
            env = Enumerable.Range(0, 20)
                .Select(index => new { name = $"SETTING_{index}", value = new string((char)('a' + index), 40) })
        });
        var chunks = new JsonStateChunker(320, 24).Chunk(json).ToArray();

        Assert.True(chunks.Length > 1);
        for (var index = 1; index < chunks.Length; index++)
        {
            var previous = Entries(chunks[index - 1]);
            var current = Entries(chunks[index]);
            Assert.Contains(current, entry => previous.Any(prior =>
                prior.Path == entry.Path && prior.Value == entry.Value));
        }
    }

    [Fact]
    public void SplitsAtRuneBoundariesWithoutLosingUnicode()
    {
        var original = string.Concat(Enumerable.Repeat("🔐é", 300));
        var chunks = new JsonStateChunker(800, 24)
            .Chunk(JsonSerializer.Serialize(original)).ToArray();
        var parts = chunks.SelectMany(Entries)
            .GroupBy(entry => entry.Start)
            .Select(group => group.First())
            .OrderBy(entry => entry.Start)
            .Select(entry => entry.Value)
            .ToArray();

        Assert.Equal(original, MergeWithOverlap(parts, 24));
        Assert.All(chunks, chunk => Assert.True(Encoding.UTF8.GetByteCount(chunk) <= 800));
    }

    [Fact]
    public void CancellationStopsLazyChunking()
    {
        using var cancellation = new CancellationTokenSource();
        var chunks = new JsonStateChunker(300, 24)
            .Chunk(JsonSerializer.Serialize(new string('x', 100_000)), cancellation.Token)
            .GetEnumerator();

        Assert.True(chunks.MoveNext());
        cancellation.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => chunks.MoveNext());
    }

    [Fact]
    public void UnsafeOverlapAndMalformedOrImpossibleInputFailClosed()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new JsonStateChunker(256, 65));
        Assert.ThrowsAny<JsonException>(() =>
            new JsonStateChunker(256, 32).Chunk("{bad").ToArray());
        Assert.Throws<InvalidOperationException>(() =>
            new JsonStateChunker(256, 32).Chunk("{\"" + new string('p', 400) + "\":1}").ToArray());
        Assert.Throws<InvalidOperationException>(() =>
            new JsonStateChunker(256, 32).Chunk(JsonSerializer.Serialize(new
            {
                name = new string('n', 400),
                value = "123e4567-e89b-12d3-a456-426614174000"
            })).ToArray());
    }

    private static Entry[] Entries(string chunk)
    {
        using var state = JsonDocument.Parse(chunk);
        return state.RootElement.GetProperty("entries").EnumerateArray().Select(element =>
        {
            var contexts = element.TryGetProperty("context", out var context) &&
                context.ValueKind == JsonValueKind.Array
                ? context.EnumerateArray().Select(item => new Context(
                    item.GetProperty("path").GetString()!,
                    Scalar(item.GetProperty("value")))).ToArray()
                : [];
            return new Entry(
                element.GetProperty("path").GetString()!,
                Scalar(element.GetProperty("value")),
                contexts,
                element.TryGetProperty("start", out var start) ? start.GetInt32() : null);
        }).ToArray();
    }

    private static string Scalar(JsonElement value) =>
        value.ValueKind == JsonValueKind.String ? value.GetString()! : value.GetRawText();

    private static string MergeWithOverlap(string[] parts, int maximumOverlapBytes)
    {
        var result = parts[0];
        foreach (var part in parts.Skip(1))
        {
            var overlapCharacters = 0;
            for (var count = 1; count <= Math.Min(result.Length, part.Length); count++)
            {
                var suffix = result[^count..];
                if (suffix == part[..count] && Encoding.UTF8.GetByteCount(suffix) <= maximumOverlapBytes)
                {
                    overlapCharacters = count;
                }
            }
            result += part[overlapCharacters..];
        }
        return result;
    }

    private sealed record Entry(string Path, string Value, Context[] Context, int? Start);
    private sealed record Context(string Path, string Value);
}
