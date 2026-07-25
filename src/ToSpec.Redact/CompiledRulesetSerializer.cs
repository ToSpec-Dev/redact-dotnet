using System.Collections.Frozen;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ToSpec.Redact;

/// <summary>
/// (De)serializes <see cref="CompiledRuleset"/> to the <c>redaction_rulesets.compiled</c>
/// jsonb column. Output is byte-stable (children sorted ordinally, defaults omitted)
/// so re-compiling identical YAML produces identical jsonb. The document carries a
/// <c>schema</c> field; a reader that meets a schema it does not know must reject
/// the ruleset (the gateway logs and keeps serving its last good snapshot — it
/// never guesses at rules it cannot fully honor).
/// </summary>
public static class CompiledRulesetSerializer
{
    public const int CurrentSchema = 1;

    public static string Serialize(CompiledRuleset ruleset)
    {
        ArgumentNullException.ThrowIfNull(ruleset);
        return JsonSerializer.Serialize(ToDoc(ruleset), RedactionJsonContext.Default.RulesetDoc);
    }

    /// <summary>Throws <see cref="JsonException"/> on malformed input or an unknown schema version.</summary>
    public static CompiledRuleset Deserialize(string compiledJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compiledJson);

        RulesetDoc doc = JsonSerializer.Deserialize(compiledJson, RedactionJsonContext.Default.RulesetDoc)
            ?? throw new JsonException("compiled ruleset document is null.");

        if (doc.Schema != CurrentSchema)
        {
            throw new JsonException(
                $"compiled ruleset schema {doc.Schema} is not supported (reader supports {CurrentSchema}); " +
                "refusing to apply rules that may not be fully honored.");
        }

        return new CompiledRuleset
        {
            Headers = new CompiledHeaderRules(
                ToHeaderSet(doc.Headers?.Strip), ToHeaderSet(doc.Headers?.Hash)),
            BodyRoot = FromNodeDoc(doc.Trie, isDescendant: false),
            Freetext = new FreetextConfig(
                doc.Freetext?.ScanUnknown ?? false,
                doc.Freetext?.Detectors is { } detectors
                    ? detectors.Select(ParseDetector).ToFrozenSet()
                    : FrozenSet<DetectorKind>.Empty),
            UnknownPiiPolicy = ParsePolicy(doc.Defaults?.UnknownPiiPolicy),
        };
    }

    private static RulesetDoc ToDoc(CompiledRuleset ruleset) => new()
    {
        Schema = CurrentSchema,
        Headers = ruleset.Headers.Strip.Count == 0 && ruleset.Headers.Hash.Count == 0
            ? null
            : new HeadersDoc
            {
                Strip = SortedOrNull(ruleset.Headers.Strip),
                Hash = SortedOrNull(ruleset.Headers.Hash),
            },
        Trie = ToNodeDoc(ruleset.BodyRoot),
        Freetext = !ruleset.Freetext.ScanUnknown && ruleset.Freetext.Detectors.Count == 0
            ? null
            : new FreetextDoc
            {
                ScanUnknown = ruleset.Freetext.ScanUnknown ? true : null,
                Detectors = ruleset.Freetext.Detectors.Count == 0
                    ? null
                    : ruleset.Freetext.Detectors.Select(DetectorName).Order(StringComparer.Ordinal).ToList(),
            },
        Defaults = new DefaultsDoc { UnknownPiiPolicy = PolicyName(ruleset.UnknownPiiPolicy) },
    };

    private static NodeDoc ToNodeDoc(TrieNode node) => new()
    {
        Children = node.Children.Count == 0
            ? null
            : new SortedDictionary<string, NodeDoc>(
                node.Children.ToDictionary(pair => pair.Key, pair => ToNodeDoc(pair.Value)),
                StringComparer.Ordinal),
        AnyIndex = node.AnyIndex is null ? null : ToNodeDoc(node.AnyIndex),
        Descendant = node.Descendant is null ? null : ToNodeDoc(node.Descendant),
        Action = node.Action == RedactionAction.None ? null : ActionName(node.Action),
        Mask = node.Action == RedactionAction.Mask && node.Mask != MaskShape.Full
            ? MaskName(node.Mask)
            : null,
        Freetext = node.IsFreetext ? true : null,
        Assertable = node.Assertable ? true : null,
    };

    private static TrieNode FromNodeDoc(NodeDoc? doc, bool isDescendant)
    {
        if (doc is null)
        {
            return new TrieNode { Children = TrieNode.NoChildren, IsDescendant = isDescendant };
        }

        return new TrieNode
        {
            Children = doc.Children is null || doc.Children.Count == 0
                ? TrieNode.NoChildren
                : doc.Children
                    .ToDictionary(pair => pair.Key, pair => FromNodeDoc(pair.Value, isDescendant: false))
                    .ToFrozenDictionary(StringComparer.Ordinal),
            AnyIndex = doc.AnyIndex is null ? null : FromNodeDoc(doc.AnyIndex, isDescendant: false),
            Descendant = doc.Descendant is null ? null : FromNodeDoc(doc.Descendant, isDescendant: true),
            IsDescendant = isDescendant,
            Action = doc.Action is null ? RedactionAction.None : ParseAction(doc.Action),
            Mask = doc.Mask is null ? MaskShape.Full : ParseMask(doc.Mask),
            IsFreetext = doc.Freetext ?? false,
            Assertable = doc.Assertable ?? false,
        };
    }

    private static List<string>? SortedOrNull(FrozenSet<string> set) =>
        set.Count == 0 ? null : set.Select(name => name.ToLowerInvariant()).Order(StringComparer.Ordinal).ToList();

    private static FrozenSet<string> ToHeaderSet(List<string>? names) =>
        names is null
            ? FrozenSet<string>.Empty
            : names.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private static string ActionName(RedactionAction action) => action switch
    {
        RedactionAction.Drop => "drop",
        RedactionAction.Mask => "mask",
        RedactionAction.Hash => "hash",
        RedactionAction.TokenizeTyped => "tokenize_typed",
        _ => throw new ArgumentOutOfRangeException(nameof(action), action, null),
    };

    private static RedactionAction ParseAction(string name) => name switch
    {
        "drop" => RedactionAction.Drop,
        "mask" => RedactionAction.Mask,
        "hash" => RedactionAction.Hash,
        "tokenize_typed" => RedactionAction.TokenizeTyped,
        _ => throw new JsonException($"unknown compiled action \"{name}\"."),
    };

    private static string MaskName(MaskShape mask) => mask switch
    {
        MaskShape.Last4 => "last4",
        MaskShape.Domain => "domain",
        _ => throw new ArgumentOutOfRangeException(nameof(mask), mask, null),
    };

    private static MaskShape ParseMask(string name) => name switch
    {
        "last4" => MaskShape.Last4,
        "domain" => MaskShape.Domain,
        _ => throw new JsonException($"unknown compiled mask shape \"{name}\"."),
    };

    private static string DetectorName(DetectorKind detector) => detector switch
    {
        DetectorKind.PanLuhn => "pan_luhn",
        DetectorKind.Email => "email",
        _ => throw new ArgumentOutOfRangeException(nameof(detector), detector, null),
    };

    private static DetectorKind ParseDetector(string name) => name switch
    {
        "pan_luhn" => DetectorKind.PanLuhn,
        "email" => DetectorKind.Email,
        _ => throw new JsonException($"unknown compiled detector \"{name}\"."),
    };

    private static string PolicyName(UnknownPiiPolicy policy) => policy switch
    {
        UnknownPiiPolicy.Off => "off",
        UnknownPiiPolicy.DetectAndHash => "detect_and_hash",
        UnknownPiiPolicy.DetectAndDrop => "detect_and_drop",
        _ => throw new ArgumentOutOfRangeException(nameof(policy), policy, null),
    };

    private static UnknownPiiPolicy ParsePolicy(string? name) => name switch
    {
        null or "detect_and_hash" => UnknownPiiPolicy.DetectAndHash,
        "off" => UnknownPiiPolicy.Off,
        "detect_and_drop" => UnknownPiiPolicy.DetectAndDrop,
        _ => throw new JsonException($"unknown compiled unknown-PII policy \"{name}\"."),
    };

    internal sealed class RulesetDoc
    {
        public int Schema { get; set; }

        public HeadersDoc? Headers { get; set; }

        public NodeDoc? Trie { get; set; }

        public FreetextDoc? Freetext { get; set; }

        public DefaultsDoc? Defaults { get; set; }
    }

    internal sealed class HeadersDoc
    {
        public List<string>? Strip { get; set; }

        public List<string>? Hash { get; set; }
    }

    internal sealed class NodeDoc
    {
        public SortedDictionary<string, NodeDoc>? Children { get; set; }

        public NodeDoc? AnyIndex { get; set; }

        public NodeDoc? Descendant { get; set; }

        public string? Action { get; set; }

        public string? Mask { get; set; }

        public bool? Freetext { get; set; }

        public bool? Assertable { get; set; }
    }

    internal sealed class FreetextDoc
    {
        public bool? ScanUnknown { get; set; }

        public List<string>? Detectors { get; set; }
    }

    internal sealed class DefaultsDoc
    {
        public string? UnknownPiiPolicy { get; set; }
    }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(CompiledRulesetSerializer.RulesetDoc))]
internal sealed partial class RedactionJsonContext : JsonSerializerContext;
