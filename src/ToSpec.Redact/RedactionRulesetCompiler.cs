using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ToSpec.Redact;

/// <summary>One compile diagnostic: a YAML-pointer-ish location plus a human message.</summary>
public sealed record RulesetCompileError(string Location, string Message)
{
    public override string ToString() => $"{Location}: {Message}";
}

/// <summary>Compile output: a ruleset, or the full list of everything wrong with the source.</summary>
public sealed record RulesetCompileResult(
    CompiledRuleset? Ruleset, IReadOnlyList<RulesetCompileError> Errors)
{
    public bool Success => Ruleset is not null;
}

/// <summary>
/// YAML → <see cref="CompiledRuleset"/> (SPEC-cert-gateway-architecture §5.1/§5.2:
/// "rules compile at config-publish time"). Errors are collected across the whole
/// document, not fail-fast, and each names what IS supported — a rejected publish
/// must tell the author how to fix every problem in one round trip (the S2.1
/// error-message standard, applied early).
/// </summary>
public static class RedactionRulesetCompiler
{
    private static readonly string[] KnownActions = ["drop", "mask", "hash", "tokenize_typed"];
    private static readonly string[] KnownKeeps = ["last4", "domain"];
    private static readonly string[] KnownDetectors = ["pan_luhn", "email"];
    private static readonly string[] KnownPolicies = ["off", "detect_and_hash", "detect_and_drop"];

    public static RulesetCompileResult Compile(string sourceYaml)
    {
        var errors = new List<RulesetCompileError>();

        RedactionRulesYaml? doc = ParseYaml(sourceYaml, errors);
        if (doc is null)
        {
            return new RulesetCompileResult(null, errors);
        }

        FrozenSet<string> strip = CompileHeaderList(doc.Headers?.Strip, "headers.strip", errors);
        FrozenSet<string> hash = CompileHeaderList(doc.Headers?.Hash, "headers.hash", errors);

        var trie = new TrieBuilder();
        CompileBodyRules(doc.Body, trie, errors);
        CompileFreetextFields(doc.Freetext?.Fields, trie, errors);

        FrozenSet<DetectorKind> detectors = CompileDetectors(doc.Freetext?.Detectors, errors);
        bool scanUnknown = doc.Freetext?.ScanUnknown ?? false;
        if ((scanUnknown || (doc.Freetext?.Fields?.Count ?? 0) > 0) && detectors.Count == 0)
        {
            errors.Add(new RulesetCompileError(
                "freetext.detectors",
                "freetext scanning is configured (fields and/or scan_unknown) but no detectors are " +
                $"listed — nothing would be detected. Available detectors: {string.Join(", ", KnownDetectors)}."));
        }

        UnknownPiiPolicy policy = CompilePolicy(doc.Defaults?.UnknownPiiPolicy, errors);

        if (errors.Count > 0)
        {
            return new RulesetCompileResult(null, errors);
        }

        return new RulesetCompileResult(
            new CompiledRuleset
            {
                Headers = new CompiledHeaderRules(strip, hash),
                BodyRoot = trie.Freeze(),
                Freetext = new FreetextConfig(scanUnknown, detectors),
                UnknownPiiPolicy = policy,
            },
            errors);
    }

    private static RedactionRulesYaml? ParseYaml(string sourceYaml, List<RulesetCompileError> errors)
    {
        if (string.IsNullOrWhiteSpace(sourceYaml))
        {
            errors.Add(new RulesetCompileError("$", "the ruleset document is empty."));
            return null;
        }

        IDeserializer deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .Build();

        // The spec's example nests the rules under a `redaction:` root key; a bare
        // document (headers/body/freetext at top level) is accepted too. Try bare
        // first and keep its error — it is the better message for typos.
        try
        {
            RedactionRulesYaml? bare = deserializer.Deserialize<RedactionRulesYaml>(sourceYaml);
            if (bare is not null)
            {
                return bare;
            }

            errors.Add(new RulesetCompileError("$", "the ruleset document is empty."));
            return null;
        }
        catch (YamlException bareException)
        {
            try
            {
                RedactionRulesYaml? wrapped = deserializer
                    .Deserialize<RedactionDocumentYaml>(sourceYaml)?.Redaction;
                if (wrapped is not null)
                {
                    return wrapped;
                }
            }
            catch (YamlException)
            {
                // Fall through to report the bare-document error.
            }

            errors.Add(new RulesetCompileError(
                $"line {bareException.Start.Line}", CleanYamlMessage(bareException)));
            return null;
        }
    }

    private static string CleanYamlMessage(YamlException exception)
    {
        // YamlDotNet nests the useful part ("Property 'headerz' not found on type …")
        // in the inner exception; surface it without the CLR type noise.
        string message = exception.InnerException?.Message ?? exception.Message;
        return message.Replace(typeof(RedactionRulesYaml).FullName!, "the ruleset", StringComparison.Ordinal);
    }

    private static FrozenSet<string> CompileHeaderList(
        List<string>? names, string location, List<RulesetCompileError> errors)
    {
        if (names is null || names.Count == 0)
        {
            return FrozenSet<string>.Empty;
        }

        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < names.Count; i++)
        {
            if (string.IsNullOrWhiteSpace(names[i]))
            {
                errors.Add(new RulesetCompileError($"{location}[{i}]", "header name is empty."));
                continue;
            }

            if (!set.Add(names[i].Trim()))
            {
                errors.Add(new RulesetCompileError(
                    $"{location}[{i}]", $"\"{names[i]}\" appears more than once in {location}."));
            }
        }

        return set.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
    }

    private static void CompileBodyRules(
        List<BodyRuleYaml>? rules, TrieBuilder trie, List<RulesetCompileError> errors)
    {
        if (rules is null)
        {
            return;
        }

        for (int i = 0; i < rules.Count; i++)
        {
            string location = $"body[{i}]";
            BodyRuleYaml rule = rules[i];

            if (string.IsNullOrWhiteSpace(rule.Path))
            {
                errors.Add(new RulesetCompileError($"{location}.path", "path is required."));
                continue;
            }

            if (!JsonPathParser.TryParse(rule.Path, out IReadOnlyList<PathSegment>? segments, out string? pathError))
            {
                errors.Add(new RulesetCompileError($"{location}.path", pathError));
                continue;
            }

            RedactionAction action;
            switch (rule.Action)
            {
                case "drop":
                    action = RedactionAction.Drop;
                    break;
                case "mask":
                    action = RedactionAction.Mask;
                    break;
                case "hash":
                    action = RedactionAction.Hash;
                    break;
                case "tokenize_typed":
                    action = RedactionAction.TokenizeTyped;
                    break;
                case null or "":
                    errors.Add(new RulesetCompileError(
                        $"{location}.action",
                        $"action is required. Supported actions: {string.Join(", ", KnownActions)}."));
                    continue;
                default:
                    errors.Add(new RulesetCompileError(
                        $"{location}.action",
                        $"\"{rule.Action}\" is not a redaction action. " +
                        $"Supported actions: {string.Join(", ", KnownActions)}."));
                    continue;
            }

            MaskShape mask = MaskShape.Full;
            if (rule.Keep is not null)
            {
                if (action != RedactionAction.Mask)
                {
                    errors.Add(new RulesetCompileError(
                        $"{location}.keep", "keep only applies to action: mask."));
                    continue;
                }

                switch (rule.Keep)
                {
                    case "last4":
                        mask = MaskShape.Last4;
                        break;
                    case "domain":
                        mask = MaskShape.Domain;
                        break;
                    default:
                        errors.Add(new RulesetCompileError(
                            $"{location}.keep",
                            $"\"{rule.Keep}\" is not a mask shape. Supported: {string.Join(", ", KnownKeeps)}."));
                        continue;
                }
            }

            bool assertable = rule.Assertable ?? false;
            if (assertable && action is not (RedactionAction.Hash or RedactionAction.TokenizeTyped))
            {
                errors.Add(new RulesetCompileError(
                    $"{location}.assertable",
                    "assertable requires a value-preserving action (hash, tokenize_typed) — a dropped " +
                    "or masked value cannot back an equality assertion."));
                continue;
            }

            if (!trie.TryAddRule(segments, action, mask, assertable, out string? addError))
            {
                errors.Add(new RulesetCompileError($"{location}.path", addError));
            }
        }
    }

    private static void CompileFreetextFields(
        List<string>? fields, TrieBuilder trie, List<RulesetCompileError> errors)
    {
        if (fields is null)
        {
            return;
        }

        for (int i = 0; i < fields.Count; i++)
        {
            string location = $"freetext.fields[{i}]";
            if (string.IsNullOrWhiteSpace(fields[i]))
            {
                errors.Add(new RulesetCompileError(location, "path is required."));
                continue;
            }

            if (!JsonPathParser.TryParse(fields[i], out IReadOnlyList<PathSegment>? segments, out string? pathError))
            {
                errors.Add(new RulesetCompileError(location, pathError));
                continue;
            }

            if (!trie.TryAddFreetext(segments, out string? addError))
            {
                errors.Add(new RulesetCompileError(location, addError));
            }
        }
    }

    private static FrozenSet<DetectorKind> CompileDetectors(
        List<string>? names, List<RulesetCompileError> errors)
    {
        if (names is null || names.Count == 0)
        {
            return FrozenSet<DetectorKind>.Empty;
        }

        var set = new HashSet<DetectorKind>();
        for (int i = 0; i < names.Count; i++)
        {
            switch (names[i])
            {
                case "pan_luhn":
                    set.Add(DetectorKind.PanLuhn);
                    break;
                case "email":
                    set.Add(DetectorKind.Email);
                    break;
                default:
                    errors.Add(new RulesetCompileError(
                        $"freetext.detectors[{i}]",
                        $"\"{names[i]}\" is not an available detector. " +
                        $"Available detectors: {string.Join(", ", KnownDetectors)}."));
                    break;
            }
        }

        return set.ToFrozenSet();
    }

    private static UnknownPiiPolicy CompilePolicy(string? value, List<RulesetCompileError> errors)
    {
        switch (value)
        {
            case null:
                return UnknownPiiPolicy.DetectAndHash; // §5.1 default
            case "off":
                return UnknownPiiPolicy.Off;
            case "detect_and_hash":
                return UnknownPiiPolicy.DetectAndHash;
            case "detect_and_drop":
                return UnknownPiiPolicy.DetectAndDrop;
            default:
                errors.Add(new RulesetCompileError(
                    "defaults.unknown_pii_policy",
                    $"\"{value}\" is not an unknown-PII policy. Supported: {string.Join(", ", KnownPolicies)}."));
                return UnknownPiiPolicy.DetectAndHash;
        }
    }

    /// <summary>Mutable trie under construction; frozen into <see cref="TrieNode"/>s at the end.</summary>
    private sealed class TrieBuilder
    {
        private readonly Node _root = new();

        public bool TryAddRule(
            IReadOnlyList<PathSegment> segments, RedactionAction action, MaskShape mask,
            bool assertable, [NotNullWhen(false)] out string? error)
        {
            Node terminal = Walk(segments);
            if (terminal.Action != RedactionAction.None)
            {
                error = "duplicate rule: another body rule already targets this exact path. " +
                    "Merge the two rules — last-one-wins would be silent.";
                return false;
            }

            terminal.Action = action;
            terminal.Mask = mask;
            terminal.Assertable = assertable;
            error = null;
            return true;
        }

        public bool TryAddFreetext(
            IReadOnlyList<PathSegment> segments, [NotNullWhen(false)] out string? error)
        {
            Node terminal = Walk(segments);
            if (terminal.IsFreetext)
            {
                error = "duplicate freetext field: this exact path is already declared.";
                return false;
            }

            terminal.IsFreetext = true;
            error = null;
            return true;
        }

        public TrieNode Freeze() => Freeze(_root, isDescendant: false);

        private Node Walk(IReadOnlyList<PathSegment> segments)
        {
            Node node = _root;
            foreach (PathSegment segment in segments)
            {
                if (segment.Descendant)
                {
                    node = node.Descendant ??= new Node();
                }

                if (segment.IsWildcardIndex)
                {
                    node = node.AnyIndex ??= new Node();
                }
                else
                {
                    if (!node.Children.TryGetValue(segment.Name!, out Node? child))
                    {
                        child = new Node();
                        node.Children.Add(segment.Name!, child);
                    }

                    node = child;
                }
            }

            return node;
        }

        private static TrieNode Freeze(Node node, bool isDescendant) => new()
        {
            Children = node.Children.Count == 0
                ? TrieNode.NoChildren
                : node.Children
                    .ToDictionary(pair => pair.Key, pair => Freeze(pair.Value, isDescendant: false))
                    .ToFrozenDictionary(StringComparer.Ordinal),
            AnyIndex = node.AnyIndex is null ? null : Freeze(node.AnyIndex, isDescendant: false),
            Descendant = node.Descendant is null ? null : Freeze(node.Descendant, isDescendant: true),
            IsDescendant = isDescendant,
            Action = node.Action,
            Mask = node.Mask,
            IsFreetext = node.IsFreetext,
            Assertable = node.Assertable,
        };

        private sealed class Node
        {
            public Dictionary<string, Node> Children { get; } = new(StringComparer.Ordinal);

            public Node? AnyIndex { get; set; }

            public Node? Descendant { get; set; }

            public RedactionAction Action { get; set; }

            public MaskShape Mask { get; set; }

            public bool IsFreetext { get; set; }

            public bool Assertable { get; set; }
        }
    }
}
