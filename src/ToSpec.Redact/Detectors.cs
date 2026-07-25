using System.Collections.Frozen;
using System.Text;
using System.Text.RegularExpressions;

namespace ToSpec.Redact;

/// <summary>
/// The regex detector layer (SPEC-cert-gateway-architecture §5.2): source-generated
/// regexes only, RE2-style discipline — no backreferences, no lookarounds, no
/// atomic groups; bounded quantifiers throughout. PAN candidates are
/// post-validated in code (digit count, non-digit boundaries, Luhn checksum) to
/// kill false positives, which is also what lets the patterns stay simple enough
/// to obey the discipline. A cheap character pre-scan (any '@' / enough digits)
/// keeps the common clean string regex-free.
/// </summary>
public static partial class Detectors
{
    private const string PanMarker = "[redacted:pan_luhn]";
    private const string EmailMarker = "[redacted:email]";

    // 12–19 digits with optional single space/hyphen separators; 13..19 enforced
    // in code after separator strip so the pattern itself stays backtrack-cheap.
    [GeneratedRegex("[0-9](?:[ -]?[0-9]){11,18}", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex PanCandidate();

    [GeneratedRegex(@"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex EmailCandidate();

    /// <summary>
    /// Scans one string value; returns the rewritten string, or null when nothing
    /// matched. <paramref name="hashReplacement"/> = true replaces matches with
    /// deterministic HMAC tokens (declared freetext fields, detect_and_hash);
    /// false replaces with <c>[redacted:…]</c> markers (detect_and_drop).
    /// </summary>
    public static string? Scan(
        ReadOnlySpan<char> text,
        FrozenSet<DetectorKind> detectors,
        bool hashReplacement,
        RedactionKeyring keys,
        ref int detectorHits)
    {
        int digits = 0;
        bool hasAt = false;
        foreach (char c in text)
        {
            if (char.IsAsciiDigit(c))
            {
                digits++;
            }
            else if (c == '@')
            {
                hasAt = true;
            }
        }

        bool tryPan = digits >= 13 && detectors.Contains(DetectorKind.PanLuhn);
        bool tryEmail = hasAt && detectors.Contains(DetectorKind.Email);
        if (!tryPan && !tryEmail)
        {
            return null;
        }

        int firstStart = -1;
        int firstLength = 0;
        string? firstReplacement = null;
        List<(int Start, int Length, string Replacement)>? hits = null;

        if (tryPan)
        {
            foreach (ValueMatch match in PanCandidate().EnumerateMatches(text))
            {
                ReadOnlySpan<char> candidate = text.Slice(match.Index, match.Length);
                if (!IsPanBoundary(text, match) || !IsLuhnValidPan(candidate))
                {
                    continue;
                }

                AddHit(match.Index, match.Length, hashReplacement ? HmacTokenizer.Tokenize(candidate, keys) : PanMarker);
            }
        }

        if (tryEmail)
        {
            foreach (ValueMatch match in EmailCandidate().EnumerateMatches(text))
            {
                AddHit(
                    match.Index,
                    match.Length,
                    hashReplacement
                        ? HmacTokenizer.Tokenize(text.Slice(match.Index, match.Length), keys)
                        : EmailMarker);
            }
        }

        if (firstStart < 0)
        {
            return null;
        }

        if (hits is null)
        {
            detectorHits++;
            return string.Concat(text[..firstStart], firstReplacement.AsSpan(), text[(firstStart + firstLength)..]);
        }

        hits.Sort((a, b) => a.Start.CompareTo(b.Start));

        var result = new StringBuilder(text.Length);
        int position = 0;
        foreach ((int start, int length, string replacement) in hits)
        {
            if (start < position)
            {
                continue; // overlap with an earlier (already replaced) match
            }

            result.Append(text[position..start]);
            result.Append(replacement);
            position = start + length;
            detectorHits++;
        }

        result.Append(text[position..]);
        return result.ToString();

        void AddHit(int start, int length, string replacement)
        {
            if (firstStart < 0)
            {
                firstStart = start;
                firstLength = length;
                firstReplacement = replacement;
                return;
            }

            hits ??= [(firstStart, firstLength, firstReplacement!)];
            hits.Add((start, length, replacement));
        }
    }

    /// <summary>Boundary chars must not be digits — a 20+-digit run is an id, not a PAN.</summary>
    private static bool IsPanBoundary(ReadOnlySpan<char> text, ValueMatch match) =>
        (match.Index == 0 || !char.IsAsciiDigit(text[match.Index - 1]))
        && (match.Index + match.Length == text.Length || !char.IsAsciiDigit(text[match.Index + match.Length]));

    private static bool IsLuhnValidPan(ReadOnlySpan<char> candidate)
    {
        Span<char> digits = stackalloc char[19];
        int count = 0;
        foreach (char c in candidate)
        {
            if (char.IsAsciiDigit(c))
            {
                if (count == digits.Length)
                {
                    return false; // > 19 digits is not a PAN
                }

                digits[count++] = c;
            }
        }

        if (count < 13)
        {
            return false;
        }

        int sum = 0;
        bool doubleIt = false;
        for (int i = count - 1; i >= 0; i--)
        {
            int digit = digits[i] - '0';
            if (doubleIt)
            {
                digit *= 2;
                if (digit > 9)
                {
                    digit -= 9;
                }
            }

            sum += digit;
            doubleIt = !doubleIt;
        }

        return sum % 10 == 0;
    }
}
