using System.Buffers;

namespace ToSpec.Redact;

/// <summary>
/// Format-neutral body redaction (SPEC-cert-gateway-architecture §5.2). One
/// implementation per <c>capture_events.content_format</c> value; JSON shipped in
/// S1.3, XML in S4.6. Implementations are pure CPU
/// over in-memory buffers (hence synchronous), stateless, and shared across
/// requests. A redactor never throws for bad input: malformed bodies come back
/// as <see cref="RedactionStatus.MalformedInput"/> and the caller owns the
/// safety policy (the gateway drops the body rather than persist unredacted
/// bytes).
/// </summary>
public interface IBodyRedactor
{
    /// <summary>The <c>content_format</c> value this redactor handles ("json").</summary>
    string Format { get; }

    RedactionResult Redact(
        in ReadOnlySequence<byte> input,
        IBufferWriter<byte> output,
        CompiledRuleset rules,
        RedactionKeyring keys);
}

public enum RedactionStatus
{
    /// <summary>The output buffer holds the complete redacted body.</summary>
    Rewritten = 0,

    /// <summary>Input was not valid; output is garbage and must be discarded.</summary>
    MalformedInput = 1,
}

/// <summary>Outcome plus counts for metrics/audit (values hit by path rules; detector replacements).</summary>
public readonly record struct RedactionResult(
    RedactionStatus Status, int ValuesRedacted, int DetectorHits);

/// <summary>
/// Content-format → redactor. Null for formats without an implementation
/// (text/binary have no structured redactor by design) — the caller decides
/// what an unhandled format means; the gateway's answer is "do not persist the
/// body if the ruleset has body rules".
/// </summary>
public static class BodyRedactorRegistry
{
    public static IBodyRedactor? Resolve(string? contentFormat) => contentFormat switch
    {
        "json" => JsonBodyRedactor.Instance,
        "xml" => XmlBodyRedactor.Instance,
        _ => null,
    };
}
