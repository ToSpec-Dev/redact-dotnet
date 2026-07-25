using System.Diagnostics.CodeAnalysis;

namespace ToSpec.Redact;

/// <summary>
/// One segment of a parsed redaction path. <see cref="Name"/> null means a
/// wildcard array index (<c>[*]</c>); <see cref="Descendant"/> means the segment
/// was reached via recursive descent (<c>..</c>).
/// </summary>
public readonly record struct PathSegment(string? Name, bool Descendant)
{
    public bool IsWildcardIndex => Name is null;
}

/// <summary>
/// Parser for the JSONPath subset admitted in redaction paths
/// (SPEC-cert-gateway-architecture §5.2): child (<c>$.a.b</c>, <c>$['a b']</c>),
/// recursive descent (<c>$..name</c>), wildcard array index (<c>[*]</c>).
/// Filter expressions, numeric indexes, slices and unions are excluded by design —
/// they are rejected here with messages that name the supported subset, because a
/// redaction path that silently matched nothing would be a data leak.
/// </summary>
public static class JsonPathParser
{
    public const string SupportedSubset =
        "child ($.a.b), quoted child ($['a b']), recursive descent ($..name), wildcard array index ([*])";

    /// <param name="path">The JSONPath text to parse.</param>
    /// <param name="segments">Parsed segments on success.</param>
    /// <param name="error">Author-facing diagnostic on failure.</param>
    /// <param name="subject">What the caller calls a path in its error messages —
    /// "redaction path" (default, S1.3 rulesets) or e.g. "assertion path" (S2.1 suites).</param>
    public static bool TryParse(
        string path,
        [NotNullWhen(true)] out IReadOnlyList<PathSegment>? segments,
        [NotNullWhen(false)] out string? error,
        string subject = "redaction path")
    {
        segments = null;

        if (string.IsNullOrWhiteSpace(path))
        {
            error = "path is empty.";
            return false;
        }

        if (path[0] != '$')
        {
            error = $"\"{path}\" — a {subject} must start with '$'.";
            return false;
        }

        var result = new List<PathSegment>();
        int i = 1;
        while (i < path.Length)
        {
            bool descendant = false;
            if (path[i] == '.')
            {
                i++;
                if (i < path.Length && path[i] == '.')
                {
                    descendant = true;
                    i++;
                }

                if (i >= path.Length)
                {
                    error = $"\"{path}\" — trailing '.' without a segment.";
                    return false;
                }

                // "$.name" / "$..name"; "$..['name']" and "$..[*]" fall through to '['.
                if (path[i] != '[')
                {
                    if (!TryReadBareName(path, ref i, out string? name, out error))
                    {
                        return false;
                    }

                    result.Add(new PathSegment(name, descendant));
                    continue;
                }
            }

            if (i < path.Length && path[i] == '[')
            {
                if (!TryReadBracket(path, ref i, subject, out PathSegment segment, out error))
                {
                    return false;
                }

                result.Add(segment with { Descendant = descendant });
                continue;
            }

            error = $"\"{path}\" — unexpected character '{path[i]}' at position {i}. " +
                $"Supported: {SupportedSubset}.";
            return false;
        }

        if (result.Count == 0)
        {
            error = $"\"{path}\" — '$' alone selects the whole body; a {subject} must name a location.";
            return false;
        }

        segments = result;
        error = null;
        return true;
    }

    private static bool TryReadBareName(
        string path, ref int i, [NotNullWhen(true)] out string? name, [NotNullWhen(false)] out string? error)
    {
        int start = i;
        while (i < path.Length && path[i] is not ('.' or '['))
        {
            char c = path[i];
            if (!char.IsAsciiLetterOrDigit(c) && c is not ('_' or '-'))
            {
                name = null;
                error = $"\"{path}\" — '{c}' is not valid in a bare segment name; " +
                    "quote names with special characters as ['name'].";
                return false;
            }

            i++;
        }

        if (i == start)
        {
            name = null;
            error = $"\"{path}\" — empty segment name at position {start}.";
            return false;
        }

        name = path[start..i];
        error = null;
        return true;
    }

    private static bool TryReadBracket(
        string path, ref int i, string subject, out PathSegment segment, [NotNullWhen(false)] out string? error)
    {
        segment = default;
        int start = i;
        i++; // consume '['

        if (i < path.Length && path[i] == '*')
        {
            if (i + 1 >= path.Length || path[i + 1] != ']')
            {
                error = $"\"{path}\" — '[*' must close as '[*]'.";
                return false;
            }

            i += 2;
            segment = new PathSegment(null, false);
            error = null;
            return true;
        }

        if (i < path.Length && path[i] == '\'')
        {
            i++;
            int nameStart = i;
            while (i < path.Length && path[i] != '\'')
            {
                i++;
            }

            if (i >= path.Length || i + 1 >= path.Length || path[i + 1] != ']')
            {
                error = $"\"{path}\" — quoted segment starting at position {start} must close as ['name'].";
                return false;
            }

            if (i == nameStart)
            {
                error = $"\"{path}\" — empty quoted segment name.";
                return false;
            }

            segment = new PathSegment(path[nameStart..i], false);
            i += 2; // consume closing quote and ']'
            error = null;
            return true;
        }

        // Precise messages for the excluded constructs — these are the ones users will try.
        error = i < path.Length && path[i] == '?'
            ? $"\"{path}\" — filter expressions are not supported in {subject}s. Supported: {SupportedSubset}."
            : i < path.Length && char.IsAsciiDigit(path[i])
                ? $"\"{path}\" — numeric array indexes are not supported in {subject}s " +
                    $"(a path pinned to one index breaks silently when the array grows); use [*]. " +
                    $"Supported: {SupportedSubset}."
                : $"\"{path}\" — unsupported bracket segment at position {start}. Supported: {SupportedSubset}.";
        return false;
    }
}
