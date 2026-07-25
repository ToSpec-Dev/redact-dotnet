using System.Collections.Frozen;

namespace ToSpec.Redact;

/// <summary>
/// One node of the compiled body-rule trie (SPEC-cert-gateway-architecture §5.2:
/// "rules compile at config-publish time into a path-trie evaluated during the
/// stream"). The JSONPath subset maps onto three edge kinds:
/// <list type="bullet">
/// <item><see cref="Children"/> — child segment (<c>.name</c> / <c>['name']</c>);</item>
/// <item><see cref="AnyIndex"/> — wildcard array index (<c>[*]</c>);</item>
/// <item><see cref="Descendant"/> — recursive descent (<c>..</c>): the child node has
/// <see cref="IsDescendant"/> set and stays active at every depth below the point it
/// was entered (the matcher keeps it in the active set instead of a structural
/// self-loop, so the trie stays acyclic and serializable).</item>
/// </list>
/// A node with <see cref="Action"/> ≠ None (or <see cref="IsFreetext"/>) is a rule
/// terminal; interior nodes carry no behavior.
/// </summary>
public sealed class TrieNode
{
    public static readonly FrozenDictionary<string, TrieNode> NoChildren =
        FrozenDictionary<string, TrieNode>.Empty;

    public required FrozenDictionary<string, TrieNode> Children { get; init; }

    public TrieNode? AnyIndex { get; init; }

    public TrieNode? Descendant { get; init; }

    public bool IsDescendant { get; init; }

    public RedactionAction Action { get; init; }

    public MaskShape Mask { get; init; }

    /// <summary>Declared <c>freetext.fields</c> terminal — detector scan with hash replacement.</summary>
    public bool IsFreetext { get; init; }

    /// <summary>Recorded for the S2.1 publish-gate redaction-compatibility check; no gateway behavior.</summary>
    public bool Assertable { get; init; }

    public bool HasEdges => Children.Count > 0 || AnyIndex is not null || Descendant is not null;
}
