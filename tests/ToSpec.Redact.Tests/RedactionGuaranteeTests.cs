using System.Buffers;
using System.Text;
using Xunit;

namespace ToSpec.Redact.Tests;

/// <summary>
/// The package-local structural guarantee: sensitive values fed to the engine never
/// survive into its output buffer. This is the standalone twin of the platform's
/// gateway-side raw-column-scan test (which proves the same property end-to-end through
/// Postgres). Here we prove it at the engine boundary, with no DB and no platform code —
/// a Luhn-valid PAN and auth-shaped secrets in a body come out tokenized/dropped, and
/// the raw bytes are absent from the redacted output.
/// </summary>
public sealed class RedactionGuaranteeTests
{
    // A Visa test PAN that passes Luhn, and an auth-shaped bearer secret.
    private const string Pan = "4111111111111111";
    private const string BearerSecret = "tsk-secret-sentinel-9d1f7c2ab4";

    private static readonly RedactionKeyring Keys = new(new byte[32], hmacKeyVersion: 1);

    [Fact]
    public void TargetedPan_HashedByRule_RawNeverInOutput()
    {
        CompiledRuleset rules = Compile(
            """
            body:
              - { path: "$.payment.cardNumber", action: hash }
            """);

        string body = $$$"""{"payment":{"cardNumber":"{{{Pan}}}"}}""";
        (RedactionResult result, string output) = Redact(rules, body);

        Assert.Equal(RedactionStatus.Rewritten, result.Status);
        Assert.DoesNotContain(Pan, output, StringComparison.Ordinal);
        Assert.Contains("\"cardNumber\":\"tsr_v1_", output, StringComparison.Ordinal);
    }

    [Fact]
    public void UndeclaredPanAndEmail_InFreetext_DetectedAndHashed_RawNeverInOutput()
    {
        // No path rule targets these fields; the free-text detector layer must catch
        // the PAN (Luhn-validated) and the email in otherwise-unmodeled string values.
        CompiledRuleset rules = Compile(
            """
            freetext:
              scan_unknown: true
              detectors: [pan_luhn, email]
            defaults:
              unknown_pii_policy: detect_and_hash
            """);

        string body = $$$"""{"notes":"charge card {{{Pan}}} sent to ada.lovelace@example.com"}""";
        (RedactionResult result, string output) = Redact(rules, body);

        Assert.Equal(RedactionStatus.Rewritten, result.Status);
        Assert.DoesNotContain(Pan, output, StringComparison.Ordinal);
        Assert.DoesNotContain("ada.lovelace@example.com", output, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthShapedSecret_TargetedForDrop_RawNeverInOutput()
    {
        // Bodies can carry credentials too (e.g. an echoed Authorization value); a drop
        // rule removes the value outright — the secret must not appear anywhere in output.
        CompiledRuleset rules = Compile(
            """
            body:
              - { path: "$.headers.authorization", action: drop }
            """);

        string body = $$$"""{"headers":{"authorization":"Bearer {{{BearerSecret}}}"}}""";
        (RedactionResult _, string output) = Redact(rules, body);

        Assert.DoesNotContain(BearerSecret, output, StringComparison.Ordinal);
        Assert.DoesNotContain("Bearer ", output, StringComparison.Ordinal);
    }

    [Fact]
    public void HashIsDeterministic_SameValueSameToken_AcrossRequests()
    {
        // Deterministic tokenization is the load-bearing property for equality assertions
        // and cross-request joins surviving redaction (SPEC §5.2).
        CompiledRuleset rules = Compile(
            """
            body:
              - { path: "$.card", action: hash }
            """);

        (_, string first) = Redact(rules, $$$"""{"card":"{{{Pan}}}"}""");
        (_, string second) = Redact(rules, $$$"""{"card":"{{{Pan}}}"}""");

        Assert.Equal(first, second);
        Assert.Contains("tsr_v1_", first, StringComparison.Ordinal);
    }

    private static (RedactionResult, string) Redact(CompiledRuleset rules, string body)
    {
        var payload = new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(body));
        var output = new ArrayBufferWriter<byte>(body.Length + 256);
        RedactionResult result = JsonBodyRedactor.Instance.Redact(payload, output, rules, Keys);
        return (result, Encoding.UTF8.GetString(output.WrittenSpan));
    }

    private static CompiledRuleset Compile(string yaml)
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(yaml);
        return result.Ruleset ?? throw new InvalidOperationException(string.Join("; ", result.Errors));
    }
}
