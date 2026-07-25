namespace ToSpec.Redact;

/// <summary>
/// Body-rule actions (SPEC-cert-gateway-architecture §5.2). Numeric order is the
/// destructiveness ranking: when several rules match one value, the highest wins
/// (Drop &gt; Hash &gt; TokenizeTyped &gt; Mask). <see cref="TokenizeTyped"/> executes
/// exactly like <see cref="Hash"/> at the gateway — the typed shadow value lives
/// only in evaluator memory (DSL spec §7) and is an S2.x concern; the flag is
/// carried so the S2.1 publish-gate can check redaction compatibility.
/// </summary>
public enum RedactionAction
{
    None = 0,
    Mask = 1,
    TokenizeTyped = 2,
    Hash = 3,
    Drop = 4,
}

/// <summary>Shape-preserving mask variants (§5.2 "mask").</summary>
public enum MaskShape
{
    /// <summary>Value replaced by <c>***</c> (no length leak).</summary>
    Full = 0,

    /// <summary>Keep the last four characters: <c>***1234</c>.</summary>
    Last4 = 1,

    /// <summary>Email shape: <c>j***@d***.com</c> (first char of local and domain + TLD).</summary>
    Domain = 2,
}

/// <summary>The <c>defaults.unknown_pii_policy</c> knob (§5.1) for detector hits in undeclared strings.</summary>
public enum UnknownPiiPolicy
{
    Off = 0,
    DetectAndHash = 1,
    DetectAndDrop = 2,
}

/// <summary>Regex detector layer (§5.2). S1.3 ships pan_luhn and email (BUILD-PLAN); the rest arrive with demand.</summary>
public enum DetectorKind
{
    PanLuhn = 0,
    Email = 1,
}

/// <summary>The §5.2 mask shapes, shared by the JSON and XML redactors.</summary>
internal static class MaskShapes
{
    public static string Apply(ReadOnlySpan<char> value, MaskShape shape)
    {
        switch (shape)
        {
            case MaskShape.Last4:
                return value.Length > 4 ? $"***{value[^4..]}" : "***";

            case MaskShape.Domain:
            {
                // j***@d***.com — first char of local and domain + the TLD.
                int at = value.IndexOf('@');
                if (at < 1 || at == value.Length - 1)
                {
                    return "***";
                }

                ReadOnlySpan<char> domain = value[(at + 1)..];
                int lastDot = domain.LastIndexOf('.');
                return lastDot < 1
                    ? "***"
                    : $"{value[0]}***@{domain[0]}***{domain[lastDot..]}";
            }

            default:
                return "***";
        }
    }
}
