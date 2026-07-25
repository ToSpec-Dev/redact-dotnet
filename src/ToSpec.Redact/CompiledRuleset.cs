using System.Collections.Frozen;

namespace ToSpec.Redact;

/// <summary>
/// A redaction ruleset compiled at publish time (SPEC-cert-gateway-architecture
/// §5.1–5.2), the in-memory form of <c>redaction_rulesets.compiled</c>. Carries no
/// version — the DB row does; the gateway pairs the two when it builds its
/// snapshot. Immutable and shared across requests.
/// </summary>
public sealed record CompiledRuleset
{
    public required CompiledHeaderRules Headers { get; init; }

    public required TrieNode BodyRoot { get; init; }

    public required FreetextConfig Freetext { get; init; }

    public required UnknownPiiPolicy UnknownPiiPolicy { get; init; }

    /// <summary>
    /// True when the ruleset expresses any body-content intent (path rules,
    /// freetext fields, or an unknown-string sweep). The gateway uses this to
    /// decide that a body in a format without a redactor (text/binary) must not
    /// be persisted.
    /// </summary>
    public bool HasBodyRules =>
        BodyRoot.HasEdges || (Freetext.ScanUnknown && UnknownPiiPolicy != UnknownPiiPolicy.Off);
}

/// <summary>Header strip/hash lists (§5.1), case-insensitive per HTTP semantics.</summary>
public sealed record CompiledHeaderRules(FrozenSet<string> Strip, FrozenSet<string> Hash)
{
    public static readonly CompiledHeaderRules Empty = new(
        FrozenSet<string>.Empty, FrozenSet<string>.Empty);
}

/// <summary>The <c>freetext</c> block: which detectors run, and whether undeclared strings are swept.</summary>
public sealed record FreetextConfig(bool ScanUnknown, FrozenSet<DetectorKind> Detectors)
{
    public static readonly FreetextConfig None = new(false, FrozenSet<DetectorKind>.Empty);
}
