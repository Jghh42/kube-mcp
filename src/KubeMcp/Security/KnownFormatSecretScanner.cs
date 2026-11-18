using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using KubeMcp.Kubernetes;

namespace KubeMcp.Security;

/// <summary>
/// Proof-of-concept deterministic scanner for credentials in known formats that
/// remain in already-sanitized tool output. It inspects JSON string values only
/// (never property names or raw text), parses string values that are themselves
/// JSON documents, and reports the JSONPath of each match.
/// </summary>
/// <remarks>
/// Most value patterns are a curated port of rules from Gitleaks
/// (https://github.com/gitleaks/gitleaks, config/gitleaks.toml, MIT License,
/// Copyright (c) 2019 Zachary Rice). Each ported rule names its Gitleaks rule id.
/// The keyword, keyed-field, base64 private-key, and validation logic is local.
/// </remarks>
internal static partial class KnownFormatSecretScanner
{
    internal const double DefaultGenericMinEntropy = 3.0;
    internal const string KeyedFieldRuleId = "generic-keyed-field";
    internal const string AwsSecretRuleId = "aws-secret-access-key";
    private const int MatchTimeoutMilliseconds = 250;
    private const int MaxGenericValueLength = 256;

    /// <summary>
    /// A credential at <paramref name="Index"/>/<paramref name="Length"/> of the
    /// string <paramref name="Node"/>. Exact-format matches redact only that text;
    /// generic (<paramref name="WholeValue"/>) matches redact the whole value.
    /// </summary>
    /// <param name="Outer">The outermost string value in the tool output.</param>
    internal readonly record struct ScanMatch(
        JsonNode Node,
        string RuleId,
        int Index,
        int Length,
        bool WholeValue,
        EmbeddedDocument? Embedding,
        JsonNode Outer)
    {
        /// <summary>Unsanitized path; valid only before <see cref="Redact"/>.</summary>
        public string Path => Outer.GetPath();
    }

    /// <summary>A JSON document parsed from the string value <see cref="Owner"/>.</summary>
    internal sealed record EmbeddedDocument(JsonNode Owner, JsonNode Root, EmbeddedDocument? Parent)
    {
        public int Depth => Parent is null ? 0 : Parent.Depth + 1;
    }

    /// <param name="Accept">
    /// Validates the <c>value</c> group (or whole match); the second argument is the
    /// Shannon-entropy threshold that only the generic rules apply.
    /// </param>
    /// <param name="WholeValue">
    /// Generic rules have approximate boundaries, so they redact the whole value.
    /// </param>
    internal sealed record ValueRule(
        string Id,
        Regex Pattern,
        Func<string, double, bool> Accept,
        bool WholeValue = false);

    internal static readonly ValueRule[] ValueRules =
    [
        // gitleaks: private-key (header through the END line or end of body).
        new("private-key", PrivateKeyRegex(), static (value, _) => HasPemBody(value)),
        new("private-key-base64", Base64PemRegex(), static (value, _) => IsBase64PrivateKey(value)),
        // gitleaks: aws-access-token
        new("aws-access-key-id", AwsAccessKeyIdRegex(),
            static (value, _) => !value.EndsWith("EXAMPLE", StringComparison.Ordinal)),
        new(AwsSecretRuleId, AwsSecretAssignmentRegex(), static (value, _) => !IsPlaceholder(value)),
        // gitleaks: github-pat, github-oauth, github-app-token, github-refresh-token
        new("github-token", GitHubTokenRegex(), static (_, _) => true),
        // gitleaks: github-fine-grained-pat
        new("github-fine-grained-pat", GitHubFineGrainedPatRegex(), static (_, _) => true),
        // gitleaks: gitlab-pat, gitlab-pat-routable
        new("gitlab-pat", GitLabPatRegex(), static (_, _) => true),
        // gitleaks: slack-bot-token, slack-user-token, slack-app-token, slack-legacy-*
        new("slack-token", SlackTokenRegex(), static (_, _) => true),
        // gitleaks: slack-webhook-url
        new("slack-webhook-url", SlackWebhookRegex(), static (_, _) => true),
        // gitleaks: stripe-access-token (secret and restricted keys only)
        new("stripe-secret-key", StripeKeyRegex(), static (_, _) => true),
        // gitleaks: gcp-api-key
        new("google-api-key", GoogleApiKeyRegex(), static (value, _) => !IsPlaceholder(value)),
        // gitleaks: jwt, plus a decoded-header check.
        new("jwt", JwtRegex(), static (value, _) => HasJwtHeader(value)),
        new("url-credentials", UrlCredentialsRegex(),
            static (value, _) => value.Length >= 3 && !IsPlaceholder(value)),
        // gitleaks: age-secret-key
        new("age-secret-key", AgeSecretKeyRegex(), static (_, _) => true),
        new("bearer-token", BearerTokenRegex(), IsNonTrivialGenericValue, WholeValue: true),
        // gitleaks: generic-api-key (simplified: keyword must end the key token).
        new("generic-assignment", GenericAssignmentRegex(), IsNonTrivialGenericValue, WholeValue: true),
    ];

    internal static IEnumerable<string> RuleIds =>
        ValueRules.Select(rule => rule.Id).Append(KeyedFieldRuleId).Distinct(StringComparer.Ordinal);

    /// <summary>
    /// Returns every accepted match. A regex timeout, or an embedded JSON document
    /// beyond the depth budget, fails closed with a fixed safe category.
    /// </summary>
    internal static List<ScanMatch> Scan(
        JsonNode? root,
        CancellationToken cancellationToken,
        double genericMinEntropy = DefaultGenericMinEntropy,
        IReadOnlyList<ValueRule>? rules = null,
        IReadOnlySet<string>? disabledRules = null)
    {
        var matches = new List<ScanMatch>();
        var context = new ScanContext(
            (rules ?? ValueRules).Where(rule => disabledRules?.Contains(rule.Id) != true).ToArray(),
            disabledRules?.Contains(AwsSecretRuleId) != true,
            disabledRules?.Contains(KeyedFieldRuleId) != true,
            genericMinEntropy,
            matches);
        try
        {
            Visit(root, keyContext: null, embedding: null, context, cancellationToken);
        }
        catch (RegexMatchTimeoutException)
        {
            throw new KubernetesReadException(
                "The credential scan did not complete.",
                KubernetesErrorCategory.CredentialScanFailed);
        }

        return matches;
    }

    private static void Visit(
        JsonNode? node,
        string? keyContext,
        EmbeddedDocument? embedding,
        ScanContext context,
        CancellationToken cancellationToken)
    {
        switch (node)
        {
            case JsonObject jsonObject:
                foreach (var (name, child) in jsonObject)
                {
                    // `{name: X, value: Y}` (env vars, Helm `set` lists) keys Y by X.
                    var childKey = name == "value" && StringValue(jsonObject["name"]) is { } siblingName
                        ? siblingName
                        : name;
                    Visit(child, childKey, embedding, context, cancellationToken);
                }

                break;
            case JsonArray jsonArray:
                string? previous = null;
                foreach (var child in jsonArray)
                {
                    // `["--client-secret", Y]` container args key Y by the preceding flag.
                    var childKey = previous is { Length: > 1 } flag && flag[0] == '-' && !flag.Contains('=')
                        ? flag.TrimStart('-')
                        : null;
                    Visit(child, childKey, embedding, context, cancellationToken);
                    previous = StringValue(child);
                }

                break;
            case JsonValue when StringValue(node) is { } value:
                cancellationToken.ThrowIfCancellationRequested();
                if (ParseEmbeddedJson(value) is { } embedded)
                {
                    // For example kubectl.kubernetes.io/last-applied-configuration:
                    // scan it as a tree so keys and escaped newlines are decoded.
                    Visit(embedded, keyContext: null, new EmbeddedDocument(node, embedded, embedding), context, cancellationToken);
                }
                else
                {
                    ScanString(node, value, keyContext, embedding, context, cancellationToken);
                }

                break;
        }
    }

    private static void ScanString(
        JsonNode node,
        string value,
        string? keyContext,
        EmbeddedDocument? embedding,
        ScanContext context,
        CancellationToken cancellationToken)
    {
        if (IsKubeMcpSafeValue(value))
        {
            return;
        }

        foreach (var rule in context.Rules)
        {
            for (var match = rule.Pattern.Match(value); match.Success; match = match.NextMatch())
            {
                // Each match call is bounded by the regex timeout; the request
                // deadline bounds the number of rejected candidates.
                cancellationToken.ThrowIfCancellationRequested();
                var group = match.Groups["value"];
                var credential = group.Success ? group : match;
                if (rule.Accept(credential.Value, context.MinEntropy))
                {
                    // A bounded pattern that stopped before the token ended (no `end`
                    // capture) has uncertain extent, so the whole value is redacted.
                    var incomplete = rule.Pattern.GroupNumberFromName("end") >= 0 && !match.Groups["end"].Success;
                    context.Matches.Add(new ScanMatch(
                        node, rule.Id, credential.Index, credential.Length, rule.WholeValue || incomplete, embedding, Outermost(node, embedding)));
                }
            }
        }

        if (keyContext is null)
        {
            return;
        }

        if (context.AwsKeyedRule && AwsSecretKeyNameRegex().IsMatch(keyContext) && AwsSecretValueRegex().IsMatch(value))
        {
            context.Matches.Add(new ScanMatch(node, AwsSecretRuleId, 0, value.Length, false, embedding, Outermost(node, embedding)));
        }

        if (context.KeyedFieldRule &&
            KeyedSecretNameRegex().IsMatch(keyContext) &&
            !DigestKeyNameRegex().IsMatch(keyContext) &&
            IsNonTrivialGenericValue(value, context.MinEntropy))
        {
            context.Matches.Add(new ScanMatch(node, KeyedFieldRuleId, 0, value.Length, true, embedding, Outermost(node, embedding)));
        }
    }

    /// <summary>
    /// Redacts matches in place. Exact-format matches replace only the matched text.
    /// A generic match replaces the whole value unless exact-format matches already
    /// cover its credential text. Embedded JSON documents are redacted as trees and
    /// re-serialized into their owning string.
    /// </summary>
    internal static void Redact(IReadOnlyList<ScanMatch> matches)
    {
        foreach (var group in matches.GroupBy(match => match.Node))
        {
            var value = group.Key.GetValue<string>();
            var exact = group.Where(match => !match.WholeValue).OrderBy(match => match.Index).ToList();
            var whole = group.FirstOrDefault(match => match.WholeValue && !IsCovered(match, exact));
            if (whole.Node is not null)
            {
                group.Key.ReplaceWith(RedactionMarker(whole.RuleId));
                continue;
            }

            var redacted = new StringBuilder(value.Length);
            var position = 0;
            foreach (var match in exact)
            {
                var end = match.Index + match.Length;
                if (end <= position)
                {
                    continue;
                }

                if (match.Index >= position)
                {
                    redacted.Append(value, position, match.Index - position).Append(RedactionMarker(match.RuleId));
                }

                position = end;
            }

            group.Key.ReplaceWith(redacted.Append(value, position, value.Length - position).ToString());
        }

        // Innermost documents first, so outer documents serialize redacted inner text.
        var documents = matches
            .SelectMany(match => Ancestors(match.Embedding))
            .Distinct()
            .OrderByDescending(document => document.Depth);
        foreach (var document in documents)
        {
            document.Owner.ReplaceWith(document.Root.ToJsonString(EmbeddedSerializerOptions));
        }
    }

    private static readonly JsonSerializerOptions EmbeddedSerializerOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static bool IsCovered(ScanMatch match, List<ScanMatch> exact)
    {
        // Exact spans are sorted; extend a covered prefix across adjacent spans.
        var covered = match.Index;
        foreach (var span in exact)
        {
            if (span.Index <= covered && span.Index + span.Length > covered)
            {
                covered = span.Index + span.Length;
            }
        }

        return covered >= match.Index + match.Length;
    }

    private static JsonNode Outermost(JsonNode node, EmbeddedDocument? embedding)
    {
        for (; embedding is not null; embedding = embedding.Parent)
        {
            node = embedding.Owner;
        }

        return node;
    }

    /// <summary>
    /// JSONPath of the outermost value for logging; call before <see cref="Redact"/>.
    /// Object keys that look like credentials or fingerprints, or that are long or
    /// unusual, are replaced with <c>*</c> because map keys can hold arbitrary data.
    /// </summary>
    internal static string LogPath(ScanMatch match)
    {
        var segments = new List<string>();
        for (var node = match.Outer; node.Parent is { } parent; node = parent)
        {
            segments.Add(parent is JsonArray
                ? $"[{node.GetElementIndex()}]"
                : SafeKey(node.GetPropertyName()));
        }

        segments.Reverse();
        return "$" + string.Concat(segments);
    }

    private static string SafeKey(string key)
    {
        if (key.Length > 63 ||
            key.Any(c => char.IsControl(c) || c is '\'' or '\\') ||
            IsKubeMcpSafeValue(key) ||
            ValueRules.Any(rule => !rule.WholeValue && rule.Pattern.IsMatch(key)))
        {
            return "[*]";
        }

        return SimpleKeyRegex().IsMatch(key) ? "." + key : $"['{key}']";
    }

    private static IEnumerable<EmbeddedDocument> Ancestors(EmbeddedDocument? document)
    {
        for (; document is not null; document = document.Parent)
        {
            yield return document;
        }
    }

    private static readonly JsonDocumentOptions EmbeddedDocumentOptions = new()
    {
        MaxDepth = 64,
        AllowDuplicateProperties = false
    };

    /// <summary>
    /// Parses a string that is a JSON document. Text that is not JSON, or JSON with
    /// duplicate property names, is scanned as raw text instead. A valid document
    /// deeper than the depth budget fails closed rather than falling back.
    /// </summary>
    private static JsonNode? ParseEmbeddedJson(string value)
    {
        var trimmed = value.AsSpan().Trim();
        if (trimmed.Length < 2 || !(trimmed[0] == '{' && trimmed[^1] == '}' || trimmed[0] == '[' && trimmed[^1] == ']'))
        {
            return null;
        }

        try
        {
            return JsonNode.Parse(value, documentOptions: EmbeddedDocumentOptions);
        }
        catch (JsonException)
        {
        }

        try
        {
            using var unbounded = JsonDocument.Parse(value, new JsonDocumentOptions { MaxDepth = 4096 });
        }
        catch (JsonException)
        {
            // Not JSON (for example a template); scan as text.
            return null;
        }

        try
        {
            using var withinDepth = JsonDocument.Parse(value, new JsonDocumentOptions { MaxDepth = EmbeddedDocumentOptions.MaxDepth });
            return null; // Valid apart from duplicate property names; scan as text.
        }
        catch (JsonException)
        {
            throw new KubernetesReadException(
                "An embedded JSON document exceeded the credential scan depth.",
                KubernetesErrorCategory.CredentialScanFailed);
        }
    }

    private sealed record ScanContext(
        ValueRule[] Rules,
        bool AwsKeyedRule,
        bool KeyedFieldRule,
        double MinEntropy,
        List<ScanMatch> Matches);

    private static string? StringValue(JsonNode? node) =>
        node is JsonValue value && value.GetValueKind() == JsonValueKind.String
            ? value.GetValue<string>()
            : null;

    /// <summary>
    /// Values kube-mcp itself produces: Secret HMAC fingerprints and redaction markers.
    /// </summary>
    internal static bool IsKubeMcpSafeValue(string value) =>
        FingerprintRegex().IsMatch(value) || RedactionMarkerRegex().IsMatch(value);

    internal static string RedactionMarker(string ruleId) => $"[redacted:{ruleId}]";

    internal static bool IsNonTrivialGenericValue(string value, double minEntropy)
    {
        if (value.Length is < 8 or > MaxGenericValueLength ||
            value.Any(char.IsWhiteSpace) ||
            IsPlaceholder(value) ||
            NonSecretShapeRegex().IsMatch(value))
        {
            return false;
        }

        // Kubernetes object names and namespace/name references commonly follow
        // secret-like keys; UUID-shaped tokens do not get this exemption.
        if (KubernetesNameShapeRegex().IsMatch(value) && !UuidRegex().IsMatch(value))
        {
            return false;
        }

        var classes = 0;
        classes += value.Any(char.IsAsciiLetterLower) ? 1 : 0;
        classes += value.Any(char.IsAsciiLetterUpper) ? 1 : 0;
        classes += value.Any(char.IsAsciiDigit) ? 1 : 0;
        classes += value.Any(static c => !char.IsAsciiLetterOrDigit(c)) ? 1 : 0;
        return classes >= 2 && ShannonEntropy(value) >= minEntropy;
    }

    internal static double ShannonEntropy(string value)
    {
        if (value.Length == 0)
        {
            return 0;
        }

        var counts = new Dictionary<char, int>();
        foreach (var c in value)
        {
            counts[c] = counts.GetValueOrDefault(c) + 1;
        }

        var entropy = 0.0;
        foreach (var count in counts.Values)
        {
            var p = (double)count / value.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static bool IsPlaceholder(string value)
    {
        if (value.StartsWith('$') || value.Contains("${", StringComparison.Ordinal) ||
            value.Contains("$(", StringComparison.Ordinal) || value.Contains("{{", StringComparison.Ordinal) ||
            value.Contains("%s", StringComparison.Ordinal) || (value.StartsWith('<') && value.EndsWith('>')))
        {
            return true;
        }

        if (value.All(c => c == value[0]))
        {
            return true;
        }

        return PlaceholderWordRegex().IsMatch(value);
    }

    private static bool IsBase64PrivateKey(string value)
    {
        var length = value.Length - (value.Length % 4);
        var buffer = new byte[length / 4 * 3];
        return Convert.TryFromBase64String(value[..length], buffer, out var written) &&
            Encoding.ASCII.GetString(buffer, 0, written).Contains("PRIVATE KEY-----", StringComparison.Ordinal);
    }

    private static bool HasPemBody(string block)
    {
        var bodyStart = block.IndexOf("-----", 10, StringComparison.Ordinal) + 5;
        var bodyEnd = block.IndexOf("-----END", bodyStart, StringComparison.Ordinal);
        var base64Characters = 0;
        foreach (var c in block.AsSpan(bodyStart, (bodyEnd < 0 ? block.Length : bodyEnd) - bodyStart))
        {
            base64Characters += char.IsAsciiLetterOrDigit(c) || c is '+' or '/' ? 1 : 0;
        }

        return base64Characters >= 32;
    }

    private static bool HasJwtHeader(string token)
    {
        var header = token[..token.IndexOf('.')];
        var padded = header.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        var buffer = new byte[padded.Length];
        if (!Convert.TryFromBase64String(padded, buffer, out var written) || written == 0 || buffer[0] != (byte)'{')
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(buffer.AsMemory(0, written));
            return document.RootElement.ValueKind == JsonValueKind.Object &&
                (document.RootElement.TryGetProperty("alg", out _) ||
                 document.RootElement.TryGetProperty("typ", out _));
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private const RegexOptions Options = RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture;

    // Newlines may appear literally or JSON-escaped (for example inside the
    // kubectl last-applied-configuration annotation).
    // The body class excludes '-', so it stops at the END line in linear time and
    // accepts any line width. Without an END line the block is incomplete.
    [GeneratedRegex(
        @"-----BEGIN[ A-Z0-9]{0,40}PRIVATE KEY(?: BLOCK)?-----" +
        @"(?:(?:\s|\\[rn]){1,4}[A-Za-z-]{1,40}:[^\r\n\\]{1,200}){0,4}[A-Za-z0-9+/=\s\\]{16,65536}" +
        @"(?<end>-----END[ A-Z0-9]{0,40}PRIVATE KEY(?: BLOCK)?-----)?",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex PrivateKeyRegex();

    // Base64 of "-----BEGIN"; the decoded text must name a private key.
    [GeneratedRegex(@"LS0tLS1CRUdJTi[A-Za-z0-9+/]{16,}={0,2}", Options, MatchTimeoutMilliseconds)]
    private static partial Regex Base64PemRegex();

    [GeneratedRegex(@"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b", Options, MatchTimeoutMilliseconds)]
    private static partial Regex AwsAccessKeyIdRegex();

    [GeneratedRegex(
        @"(?i)aws[\w.-]{0,20}?secret[\w.-]{0,20}[""']?[ \t]{0,3}(?:=|:=|=>|:)[ \t]{0,3}[""']?" +
        @"(?<value>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex AwsSecretAssignmentRegex();

    [GeneratedRegex(@"\bgh[pousr]_[A-Za-z0-9]{36}\b", Options, MatchTimeoutMilliseconds)]
    private static partial Regex GitHubTokenRegex();

    [GeneratedRegex(@"\bgithub_pat_\w{82}\b", Options, MatchTimeoutMilliseconds)]
    private static partial Regex GitHubFineGrainedPatRegex();

    [GeneratedRegex(@"\bglpat-[\w.-]{20,64}(?:(?<end>)(?![\w.-]))?", Options, MatchTimeoutMilliseconds)]
    private static partial Regex GitLabPatRegex();

    [GeneratedRegex(
        @"\b(?:xox[abposr]-(?:[0-9]{10,13}-){1,3}[A-Za-z0-9-]{8,64}|xapp-\d-[A-Z0-9]{9,12}-\d{10,14}-[a-f0-9]{32,80})" +
        @"(?:(?<end>)(?![A-Za-z0-9-]))?",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex SlackTokenRegex();

    [GeneratedRegex(
        @"https?://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}(?:(?<end>)(?![A-Za-z0-9+/]))?",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex SlackWebhookRegex();

    [GeneratedRegex(@"\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b", Options, MatchTimeoutMilliseconds)]
    private static partial Regex StripeKeyRegex();

    [GeneratedRegex(@"\bAIza[\w-]{35}(?![\w-])", Options, MatchTimeoutMilliseconds)]
    private static partial Regex GoogleApiKeyRegex();

    [GeneratedRegex(
        @"\bey[A-Za-z0-9_-]{15,1024}\.[A-Za-z0-9_-]{2,16384}\.[A-Za-z0-9_-]{0,4096}(?:(?<end>)(?![A-Za-z0-9_-]))?",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex JwtRegex();

    [GeneratedRegex(
        @"(?i)\b[a-z][a-z0-9+.-]{1,30}://[^\s:@/?#]{0,128}:(?<value>[^\s@/?#]{1,256})@[a-z0-9\[]",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex UrlCredentialsRegex();

    [GeneratedRegex(@"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b", Options, MatchTimeoutMilliseconds)]
    private static partial Regex AgeSecretKeyRegex();

    [GeneratedRegex(@"(?i)\bbearer[ \t]+(?<value>[A-Za-z0-9._~+/-]{8,4096}=*)", Options, MatchTimeoutMilliseconds)]
    private static partial Regex BearerTokenRegex();

    // The keyword must end the key token (`DB_PASSWORD=`, `"apiKey":`, `--token=`),
    // so `secretName:` or `tokenTTL=` do not match.
    [GeneratedRegex(
        @"(?i)(?:passw(?:or)?d|passphrase|pwd|secret|token|api[_.-]?key|access[_.-]?key|auth[_.-]?key|" +
        @"private[_.-]?key|credentials?)[""']?[ \t]{0,3}(?:=|:=|=>|:)[ \t]{0,3}[""'`]?" +
        @"(?<value>[^\s""'`;,&|<>(){}\[\]]{8,256})",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex GenericAssignmentRegex();

    [GeneratedRegex(
        @"(?i)(?:passw(?:or)?d|passphrase|pwd|secret|token|api[_.-]?key|access[_.-]?key|auth[_.-]?key|" +
        @"private[_.-]?key|credentials?)$",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex KeyedSecretNameRegex();

    // Helm `checksum/secret` and similar keys hold digests of secrets, not secrets.
    [GeneratedRegex(@"(?i)checksum|hash|digest|fingerprint", Options, MatchTimeoutMilliseconds)]
    private static partial Regex DigestKeyNameRegex();

    [GeneratedRegex(@"(?i)(?:aws[_.-]?)?secret[_.-]?access[_.-]?key$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex AwsSecretKeyNameRegex();

    [GeneratedRegex(@"^[A-Za-z0-9/+]{40}$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex AwsSecretValueRegex();

    [GeneratedRegex(@"^hmac-sha256:[0-9a-f]{32}$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex FingerprintRegex();

    [GeneratedRegex(@"^\[redacted:[a-z0-9-]{1,64}\]$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex RedactionMarkerRegex();

    [GeneratedRegex(
        @"(?i)example|placeholder|redacted|changeit|your[_-]|replace[_-]?me|xxxx|\*\*\*|\.\.\.",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex PlaceholderWordRegex();

    // Paths, URLs without credentials, digests, booleans, numbers, and
    // environment-variable name references (`AUTHELIA_OIDC_CLIENT_SECRET`).
    [GeneratedRegex(
        @"^(?:[/~.]|[a-z][a-z0-9+.-]*://|(?:sha1|sha256|sha512|md5):[0-9a-f]+$|(?i:true|false|null)$|[0-9.]+$|" +
        @"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$)",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex NonSecretShapeRegex();

    [GeneratedRegex(@"^[a-z0-9]+(?:[-./][a-z0-9]+)+$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex KubernetesNameShapeRegex();

    [GeneratedRegex(@"^[A-Za-z_$][A-Za-z0-9_$]*$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex SimpleKeyRegex();

    [GeneratedRegex(@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex UuidRegex();
}
