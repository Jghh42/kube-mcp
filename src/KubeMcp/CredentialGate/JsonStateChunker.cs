using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace KubeMcp.CredentialGate;

/// <summary>
/// Streams structurally contextual JSON states. Adjacent leaf entries are kept
/// together and one entry overlaps every state boundary.
/// </summary>
internal sealed class JsonStateChunker
{
    private const int MaximumContextEntries = 4;
    private static readonly int StateEnvelopeBytes =
        Encoding.UTF8.GetByteCount("{\"entries\":[]}");
    private readonly int maximumBytes;
    private readonly int overlapBytes;

    public JsonStateChunker(int maximumBytes, int overlapBytes)
    {
        if (maximumBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        }
        if (overlapBytes < 0 || overlapBytes > maximumBytes / 4)
        {
            throw new ArgumentOutOfRangeException(nameof(overlapBytes));
        }
        this.maximumBytes = maximumBytes;
        this.overlapBytes = overlapBytes;
    }

    public IEnumerable<string> Chunk(string json, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
            MaxDepth = 128
        });

        cancellationToken.ThrowIfCancellationRequested();
        var current = new List<StateEntry>();
        var currentBytes = StateEnvelopeBytes;
        var found = false;
        foreach (var leaf in EnumerateLeaves(document.RootElement, string.Empty, cancellationToken))
        {
            foreach (var entry in Normalize(leaf, cancellationToken))
            {
                cancellationToken.ThrowIfCancellationRequested();
                found = true;
                var entryBytes = SerializedEntryBytes(entry);
                if (current.Count == 0)
                {
                    current.Add(entry);
                    currentBytes += entryBytes;
                    continue;
                }

                if (currentBytes + 1 + entryBytes <= maximumBytes)
                {
                    current.Add(entry);
                    currentBytes += 1 + entryBytes;
                    continue;
                }

                yield return Serialize(current);
                cancellationToken.ThrowIfCancellationRequested();

                var overlap = current[^1];
                current = [overlap, entry];
                currentBytes = StateEnvelopeBytes + SerializedEntryBytes(overlap) + 1 + entryBytes;
                if (currentBytes > maximumBytes)
                {
                    throw new InvalidOperationException(
                        "Adjacent JSON entries cannot be safely contextualized within the state bound.");
                }
            }
        }

        if (!found || current.Count == 0)
        {
            throw new InvalidOperationException("JSON state could not be covered.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        yield return Serialize(current);
    }

    private IEnumerable<Leaf> EnumerateLeaves(
        JsonElement element,
        string path,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (element.ValueKind == JsonValueKind.Object)
        {
            var properties = element.EnumerateObject().ToArray();
            if (properties.Length == 0)
            {
                yield return new Leaf(path, element, []);
                yield break;
            }

            var scalarProperties = properties
                .Where(property => IsScalar(property.Value))
                .ToArray();
            var contextCandidates = scalarProperties
                .Where(property => property.Name.Equals("name", StringComparison.Ordinal))
                .Concat(scalarProperties
                    .Where(property => !property.Name.Equals("name", StringComparison.Ordinal))
                    .OrderBy(property => property.Name, StringComparer.Ordinal)
                    .Take(MaximumContextEntries + 1))
                .ToArray();
            foreach (var property in properties)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var propertyPath = path + "/" + Escape(property.Name);
                var availableContexts = contextCandidates
                    .Where(sibling => sibling.Name != property.Name)
                    .Select(sibling => new ContextEntry(
                        path + "/" + Escape(sibling.Name), sibling.Value))
                    .ToArray();
                var contexts = availableContexts.Where(IsIdentityContext)
                    .Concat(availableContexts.Where(context => !IsIdentityContext(context))
                        .Take(MaximumContextEntries))
                    .ToArray();
                foreach (var leaf in EnumerateLeaves(property.Value, propertyPath, cancellationToken))
                {
                    yield return leaf with
                    {
                        Context = MergeContexts(leaf.Context, contexts)
                    };
                }
            }

            yield break;
        }

        if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                foreach (var leaf in EnumerateLeaves(item, path + "/" + index, cancellationToken))
                {
                    yield return leaf;
                }
                index++;
            }

            if (index == 0)
            {
                yield return new Leaf(path, element, []);
            }
            yield break;
        }

        yield return new Leaf(path, element, []);
    }

    private IEnumerable<StateEntry> Normalize(Leaf leaf, CancellationToken cancellationToken)
    {
        var value = leaf.Value.ValueKind == JsonValueKind.String ? leaf.Value.GetString() : null;
        var contexts = SelectContexts(leaf, value, cancellationToken);
        var ordinary = new StateEntry(
            leaf.Path,
            leaf.Value,
            contexts.Count == 0 ? null : contexts,
            null,
            null);
        // Ensuring two copies fit reserves capacity for the mandatory adjacent
        // entry overlap used by the state packer.
        if (Fits([ordinary, ordinary]))
        {
            yield return ordinary;
            yield break;
        }

        if (leaf.Value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException(
                "A non-string JSON value cannot be safely contextualized within the state bound.");
        }

        var runes = value!.EnumerateRunes().ToArray();
        if (runes.Length == 0)
        {
            throw new InvalidOperationException("An empty scalar could not fit in a contextual state.");
        }

        var start = 0;
        while (start < runes.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var end = FindMaximumEnd(leaf.Path, runes, start, contexts, cancellationToken);
            var nextStart = end == runes.Length ? end : OverlapStart(runes, start, end);
            var forwardBytes = Utf8Bytes(runes, start, nextStart);
            if (end == start ||
                (end < runes.Length && forwardBytes < Math.Max(16, overlapBytes)))
            {
                // Later runes may need more JSON escaping than the initial
                // capacity probe. Retry this segment without optional siblings,
                // but never discard required identity context.
                var requiredContexts = contexts.Where(IsIdentityContext).ToArray();
                if (requiredContexts.Length < contexts.Count)
                {
                    contexts = requiredContexts;
                    continue;
                }
                throw new InvalidOperationException(
                    "Scalar overlap leaves insufficient forward progress.");
            }

            var segment = Join(runes, start, end);
            yield return new StateEntry(leaf.Path, segment, contexts, start, end);
            start = nextStart;
        }
    }

    private IReadOnlyList<ContextEntry> SelectContexts(
        Leaf leaf,
        string? value,
        CancellationToken cancellationToken)
    {
        object probeValue = leaf.Value;
        int? probeOffset = null;
        if (value is not null)
        {
            // Optional siblings must leave space for both overlap and meaningful
            // forward progress, not merely an empty value. Short values reserve
            // their complete representation instead.
            var minimumSegmentBytes = overlapBytes + Math.Max(16, overlapBytes);
            var probe = new StringBuilder();
            var bytes = 0;
            foreach (var rune in value.EnumerateRunes())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (bytes >= minimumSegmentBytes)
                {
                    break;
                }
                probe.Append(rune.ToString());
                bytes += rune.Utf8SequenceLength;
            }
            if (probe.Length < value.Length)
            {
                probeValue = probe.ToString();
                // Reserve the largest possible offset width for later segments.
                probeOffset = value.Length;
            }
        }

        var selected = new List<ContextEntry>();
        foreach (var context in leaf.Context)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ContextEntry[] candidateContexts = [.. selected, context];
            var candidate = new StateEntry(
                leaf.Path, probeValue, candidateContexts, probeOffset, probeOffset);
            var fits = Fits([candidate, candidate]);
            if (!fits && probeOffset is not null && value!.Length <= maximumBytes / 2)
            {
                // A complete ordinary value can fit even when synthetic segment
                // offsets would not. Never reject its required context merely
                // because segmentation has more framing overhead.
                var ordinary = new StateEntry(leaf.Path, leaf.Value, candidateContexts, null, null);
                fits = Fits([ordinary, ordinary]);
            }
            if (fits)
            {
                selected.Add(context);
                continue;
            }

            if (IsIdentityContext(context))
            {
                throw new InvalidOperationException(
                    "A scalar cannot retain its required name identity context.");
            }
        }
        return selected;
    }

    private static IReadOnlyList<ContextEntry> MergeContexts(
        IReadOnlyList<ContextEntry> nearest,
        IReadOnlyList<ContextEntry> inherited)
    {
        var merged = nearest.Concat(inherited)
            .GroupBy(context => context.Path, StringComparer.Ordinal)
            .Select(group => group.First())
            .ToArray();
        return merged.Where(IsIdentityContext)
            .Concat(merged.Where(context => !IsIdentityContext(context))
                .Take(MaximumContextEntries))
            .ToArray();
    }

    private static bool IsIdentityContext(ContextEntry context) =>
        context.Path.EndsWith("/name", StringComparison.Ordinal);

    private int FindMaximumEnd(
        string path,
        Rune[] runes,
        int start,
        IReadOnlyList<ContextEntry> contexts,
        CancellationToken cancellationToken)
    {
        var low = start;
        // Every rune occupies at least one serialized byte, and two entries must
        // fit. Never construct a trial proportional to the remaining input.
        var high = start + Math.Min(runes.Length - start, maximumBytes / 2);
        while (low < high)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var middle = low + ((high - low + 1) / 2);
            var candidate = new StateEntry(path, Join(runes, start, middle), contexts, start, middle);
            if (Fits([candidate, candidate]))
            {
                low = middle;
            }
            else
            {
                high = middle - 1;
            }
        }
        return low;
    }

    private int OverlapStart(Rune[] runes, int start, int end)
    {
        var overlapStart = end;
        var bytes = 0;
        while (overlapStart > start)
        {
            var runeBytes = runes[overlapStart - 1].Utf8SequenceLength;
            if (bytes + runeBytes > overlapBytes)
            {
                break;
            }
            bytes += runeBytes;
            overlapStart--;
        }
        return overlapStart;
    }

    private bool Fits(IReadOnlyList<StateEntry> entries) => StateSize(entries) <= maximumBytes;

    private static int StateSize(IReadOnlyList<StateEntry> entries) =>
        StateEnvelopeBytes +
        entries.Sum(SerializedEntryBytes) +
        Math.Max(0, entries.Count - 1);

    private static int SerializedEntryBytes(StateEntry entry) =>
        Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(entry));

    private static string Serialize(IReadOnlyList<StateEntry> entries) =>
        JsonSerializer.Serialize(new { entries });

    private static string Join(Rune[] runes, int start, int end)
    {
        var builder = new StringBuilder();
        for (var index = start; index < end; index++)
        {
            builder.Append(runes[index].ToString());
        }
        return builder.ToString();
    }

    private static int Utf8Bytes(Rune[] runes, int start, int end)
    {
        var bytes = 0;
        for (var index = start; index < end; index++)
        {
            bytes += runes[index].Utf8SequenceLength;
        }
        return bytes;
    }

    private static bool IsScalar(JsonElement element) => element.ValueKind is
        JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or
        JsonValueKind.False or JsonValueKind.Null;

    private static string Escape(string segment) =>
        segment.Replace("~", "~0", StringComparison.Ordinal)
            .Replace("/", "~1", StringComparison.Ordinal);

    private sealed record Leaf(
        string Path,
        JsonElement Value,
        IReadOnlyList<ContextEntry> Context);

    private sealed record ContextEntry(
        [property: JsonPropertyName("path")] string Path,
        [property: JsonPropertyName("value")] JsonElement Value);

    private sealed record StateEntry(
        [property: JsonPropertyName("path")] string Path,
        [property: JsonPropertyName("value")] object Value,
        [property: JsonPropertyName("context"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<ContextEntry>? Context,
        [property: JsonPropertyName("start"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? Start,
        [property: JsonPropertyName("end"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? End);
}
