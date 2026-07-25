using System.Buffers;
using System.Text;
using ToSpec.Redact;
using Xunit;

namespace ToSpec.Redact.Tests;

public sealed class JsonBodyRedactorTests
{
    private static readonly RedactionKeyring Keys = new(new byte[32], hmacKeyVersion: 1);

    private static CompiledRuleset Compile(string yaml)
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(yaml);
        Assert.True(result.Success, string.Join("; ", result.Errors));
        return result.Ruleset!;
    }

    private static (RedactionResult Result, string Output) Redact(string yaml, string json)
    {
        var output = new ArrayBufferWriter<byte>();
        RedactionResult result = JsonBodyRedactor.Instance.Redact(
            new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(json)), output, Compile(yaml), Keys);
        return (result, Encoding.UTF8.GetString(output.WrittenSpan));
    }

    private static string Token(string value) => HmacTokenizer.Tokenize(value.AsSpan(), Keys);

    // --- path matching ---

    [Fact]
    public void Redact_ChildPathString_TokenDeterministicAcrossCalls()
    {
        const string yaml = """
            body:
              - { path: "$.payment.cardNumber", action: hash }
            """;
        const string json = """{"payment":{"cardNumber":"4111111111111111","amount":12}}""";

        (RedactionResult first, string output) = Redact(yaml, json);
        (_, string second) = Redact(yaml, json);

        Assert.Equal(1, first.ValuesRedacted);
        Assert.Equal(output, second);
        Assert.Contains($"\"cardNumber\":\"{Token("4111111111111111")}\"", output, StringComparison.Ordinal);
        Assert.Contains("\"amount\":12", output, StringComparison.Ordinal);
        Assert.StartsWith("{\"payment\":", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_RecursiveDescent_MatchesAllDepths()
    {
        const string yaml = """
            body:
              - { path: "$..password", action: drop }
            """;
        (_, string output) = Redact(yaml,
            """{"password":"a","user":{"password":"b","nested":[{"password":"c","keep":1}]}}""");

        Assert.DoesNotContain("password", output, StringComparison.Ordinal);
        Assert.Contains("\"keep\":1", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_WildcardIndex_AppliesToEveryElement()
    {
        const string yaml = """
            body:
              - { path: "$.items[*].price", action: hash }
            """;
        (RedactionResult result, string output) = Redact(yaml,
            """{"items":[{"price":"1.50","sku":"a"},{"price":"2.00","sku":"b"}],"price":"3.00"}""");

        Assert.Equal(2, result.ValuesRedacted);
        Assert.DoesNotContain("1.50", output, StringComparison.Ordinal);
        Assert.DoesNotContain("2.00", output, StringComparison.Ordinal);
        Assert.Contains("\"price\":\"3.00\"", output, StringComparison.Ordinal); // top-level price unmatched
        Assert.Contains("\"sku\":\"a\"", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_DescendantThenWildcard_Matches()
    {
        const string yaml = """
            body:
              - { path: "$..cards[*]", action: drop }
            """;
        (_, string output) = Redact(yaml,
            """{"a":{"cards":["4111111111111111","5500005555555559"]},"cards":["x"]}""");

        Assert.Equal("""{"a":{"cards":[]},"cards":[]}""", output);
    }

    [Fact]
    public void Redact_EscapedPropertyName_MatchesUnescaped()
    {
        const string yaml = """
            body:
              - { path: "$.email", action: drop }
            """;
        // "email" unescapes to "email" — matching must run on the unescaped name.
        (_, string output) = Redact(yaml, """{"email":"x@y.com","ok":true}""");

        Assert.Equal("""{"ok":true}""", output);
    }

    // --- actions ---

    [Fact]
    public void Redact_DropProperty_NameAndValueAbsent()
    {
        const string yaml = """
            body:
              - { path: "$.guest.phone", action: drop }
            """;
        (_, string output) = Redact(yaml, """{"guest":{"phone":"+123","name":"g"}}""");

        Assert.Equal("""{"guest":{"name":"g"}}""", output);
    }

    [Fact]
    public void Redact_DropObjectValuedProperty_SubtreeRemoved()
    {
        const string yaml = """
            body:
              - { path: "$.card", action: drop }
            """;
        (_, string output) = Redact(yaml, """{"card":{"pan":"4111111111111111","cvv":"123"},"ok":1}""");

        Assert.Equal("""{"ok":1}""", output);
    }

    [Fact]
    public void Redact_HashOnContainerValue_PlaceholderWritten()
    {
        const string yaml = """
            body:
              - { path: "$.card", action: hash }
            """;
        (_, string output) = Redact(yaml, """{"card":{"pan":"4111111111111111"}}""");

        Assert.Equal("""{"card":"[redacted:container]"}""", output);
    }

    [Fact]
    public void Redact_MaskKeepDomain_ShapePreserved()
    {
        const string yaml = """
            body:
              - { path: "$.guest.email", action: mask, keep: domain }
            """;
        (_, string output) = Redact(yaml, """{"guest":{"email":"john@doe.example.com"}}""");

        Assert.Equal("""{"guest":{"email":"j***@d***.com"}}""", output);
    }

    [Fact]
    public void Redact_MaskKeepLast4_KeepsTail()
    {
        const string yaml = """
            body:
              - { path: "$.card", action: mask, keep: last4 }
            """;
        (_, string output) = Redact(yaml, """{"card":"4111111111111111"}""");

        Assert.Equal("""{"card":"***1111"}""", output);
    }

    [Fact]
    public void Redact_MaskNumberAndBool_TypeShapePreserved()
    {
        const string yaml = """
            body:
              - { path: "$.rate", action: mask }
              - { path: "$.smoker", action: mask }
            """;
        (_, string output) = Redact(yaml, """{"rate":129.99,"smoker":true}""");

        Assert.Equal("""{"rate":0,"smoker":false}""", output);
    }

    [Fact]
    public void Redact_HashNumber_LiteralTextTokenized()
    {
        const string yaml = """
            body:
              - { path: "$.rate", action: hash }
            """;
        (_, string output) = Redact(yaml, """{"rate":129.99}""");

        Assert.Equal($$"""{"rate":"{{Token("129.99")}}"}""", output);
    }

    [Fact]
    public void Redact_TokenizeTyped_BehavesAsHashAtGateway()
    {
        const string yaml = """
            body:
              - { path: "$.rate", action: tokenize_typed }
            """;
        (_, string output) = Redact(yaml, """{"rate":"100.00"}""");

        Assert.Equal($$"""{"rate":"{{Token("100.00")}}"}""", output);
    }

    [Fact]
    public void Redact_DropArrayElement_ElementRemovedArrayValid()
    {
        const string yaml = """
            body:
              - { path: "$.cards[*]", action: drop }
            """;
        (_, string output) = Redact(yaml, """{"cards":["a","b"],"n":1}""");

        Assert.Equal("""{"cards":[],"n":1}""", output);
    }

    [Fact]
    public void Redact_NullAtMatchedPath_PassesThrough()
    {
        const string yaml = """
            body:
              - { path: "$.email", action: hash }
            """;
        (_, string output) = Redact(yaml, """{"email":null}""");

        Assert.Equal("""{"email":null}""", output);
    }

    [Fact]
    public void Redact_OverlappingRules_MostDestructiveWins()
    {
        const string yaml = """
            body:
              - { path: "$.a.secret", action: mask }
              - { path: "$..secret", action: drop }
            """;
        (_, string output) = Redact(yaml, """{"a":{"secret":"x"},"b":1}""");

        Assert.Equal("""{"a":{},"b":1}""", output);
    }

    // --- freetext & detectors ---

    [Fact]
    public void Redact_FreetextField_LuhnValidPanHashed()
    {
        const string yaml = """
            freetext:
              fields: ["$.notes"]
              detectors: [pan_luhn]
            """;
        (RedactionResult result, string output) = Redact(yaml,
            """{"notes":"card 4111 1111 1111 1111 declined","other":"4111 1111 1111 1111"}""");

        Assert.Equal(1, result.DetectorHits);
        Assert.Contains($"\"notes\":\"card {Token("4111 1111 1111 1111")} declined\"", output, StringComparison.Ordinal);
        Assert.Contains("\"other\":\"4111 1111 1111 1111\"", output, StringComparison.Ordinal); // undeclared, no sweep
    }

    [Fact]
    public void Redact_LuhnInvalidDigitRun_Untouched()
    {
        const string yaml = """
            freetext:
              fields: ["$.notes"]
              detectors: [pan_luhn]
            """;
        // 4111111111111112 fails the Luhn checksum; 19-digit order ids stay readable.
        (RedactionResult result, string output) = Redact(yaml, """{"notes":"ref 4111111111111112"}""");

        Assert.Equal(0, result.DetectorHits);
        Assert.Contains("4111111111111112", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_TwentyDigitRun_NotAPan()
    {
        const string yaml = """
            freetext:
              fields: ["$.notes"]
              detectors: [pan_luhn]
            """;
        (RedactionResult result, string output) = Redact(yaml, """{"notes":"id 41111111111111111115"}""");

        Assert.Equal(0, result.DetectorHits);
        Assert.Contains("41111111111111111115", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_ScanUnknown_DetectAndHash_SweepsEveryString()
    {
        const string yaml = """
            freetext:
              scan_unknown: true
              detectors: [pan_luhn, email]
            defaults:
              unknown_pii_policy: detect_and_hash
            """;
        (RedactionResult result, string output) = Redact(yaml,
            """{"a":"pan 4111111111111111","deep":{"b":["mail j@d.com"]}}""");

        Assert.Equal(2, result.DetectorHits);
        Assert.DoesNotContain("4111111111111111", output, StringComparison.Ordinal);
        Assert.DoesNotContain("j@d.com", output, StringComparison.Ordinal);
        Assert.Contains(Token("4111111111111111"), output, StringComparison.Ordinal);
        Assert.Contains(Token("j@d.com"), output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_ScanUnknown_DetectAndHash_LuhnValidPanAsJsonNumber_Redacted()
    {
        // §5.2 "final sweep of the redacted output": a Luhn-valid PAN sent as a bare
        // JSON number (not a string) must not survive the detector sweep. Regression
        // for the numeric-token gap in the detector layer.
        const string yaml = """
            freetext:
              scan_unknown: true
              detectors: [pan_luhn]
            defaults:
              unknown_pii_policy: detect_and_hash
            """;
        (RedactionResult result, string output) = Redact(yaml, """{"card":4111111111111111}""");

        Assert.Equal(1, result.DetectorHits);
        Assert.DoesNotContain("4111111111111111", output, StringComparison.Ordinal);
        Assert.Equal($$"""{"card":"{{Token("4111111111111111")}}"}""", output);
    }

    [Fact]
    public void Redact_ScanUnknown_DetectAndDrop_LuhnValidPanAsJsonNumber_Marked()
    {
        const string yaml = """
            freetext:
              scan_unknown: true
              detectors: [pan_luhn]
            defaults:
              unknown_pii_policy: detect_and_drop
            """;
        (_, string output) = Redact(yaml, """{"card":4111111111111111}""");

        Assert.Equal("""{"card":"[redacted:pan_luhn]"}""", output);
    }

    [Fact]
    public void Redact_ScanUnknown_NonPanNumber_UntouchedAndStillANumber()
    {
        // Numbers that are not PANs keep their JSON number type (no accidental
        // string coercion, no perf-path regression to a marker).
        const string yaml = """
            freetext:
              scan_unknown: true
              detectors: [pan_luhn]
            defaults:
              unknown_pii_policy: detect_and_hash
            """;
        (RedactionResult result, string output) = Redact(yaml,
            """{"rate":129.99,"qty":7,"ref":4111111111111112}""");

        Assert.Equal(0, result.DetectorHits);
        Assert.Equal("""{"rate":129.99,"qty":7,"ref":4111111111111112}""", output);
    }

    [Fact]
    public void Redact_ScanUnknown_DetectAndDrop_MarkerReplacesSpan()
    {
        const string yaml = """
            freetext:
              scan_unknown: true
              detectors: [pan_luhn]
            defaults:
              unknown_pii_policy: detect_and_drop
            """;
        (_, string output) = Redact(yaml, """{"a":"pan 4111111111111111 end"}""");

        Assert.Equal("""{"a":"pan [redacted:pan_luhn] end"}""", output);
    }

    [Fact]
    public void Redact_PolicyOff_UndeclaredStringsUntouched()
    {
        const string yaml = """
            freetext:
              fields: ["$.notes"]
              detectors: [pan_luhn]
            defaults:
              unknown_pii_policy: off
            """;
        (_, string output) = Redact(yaml, """{"other":"4111111111111111"}""");

        Assert.Contains("4111111111111111", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_EmailDetector_AllOccurrencesReplaced()
    {
        const string yaml = """
            freetext:
              fields: ["$.notes"]
              detectors: [email]
            """;
        (RedactionResult result, string output) = Redact(yaml,
            """{"notes":"cc a@b.co and c@d.org please"}""");

        Assert.Equal(2, result.DetectorHits);
        Assert.Equal($$"""{"notes":"cc {{Token("a@b.co")}} and {{Token("c@d.org")}} please"}""", output);
    }

    [Fact]
    public void Redact_FreetextOnContainer_PropagatesToNestedStrings()
    {
        const string yaml = """
            freetext:
              fields: ["$.comments"]
              detectors: [email]
            """;
        (_, string output) = Redact(yaml, """{"comments":[{"text":"met j@d.com"}]}""");

        Assert.DoesNotContain("j@d.com", output, StringComparison.Ordinal);
    }

    // --- failure policy ---

    [Theory]
    [InlineData("{\"a\":")]                    // truncated
    [InlineData("{\"a\":1} trailing")]         // trailing content
    [InlineData("{\"a\":1}{\"b\":2}")]         // second top-level value
    [InlineData("{//comment\n\"a\":1}")]       // comments disallowed
    [InlineData("not json at all")]
    [InlineData("")]                           // empty — no JSON value
    [InlineData("   ")]                        // whitespace only — no JSON value
    [InlineData("\n\t ")]                      // whitespace only (mixed)
    public void Redact_MalformedInput_ReturnsMalformedInput_NeverThrows(string json)
    {
        var output = new ArrayBufferWriter<byte>();
        RedactionResult result = JsonBodyRedactor.Instance.Redact(
            new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(json)), output,
            Compile("""
                body:
                  - { path: "$.a", action: drop }
                """), Keys);

        Assert.Equal(RedactionStatus.MalformedInput, result.Status);
    }

    [Fact]
    public void Redact_DepthOver64_ReturnsMalformedInput()
    {
        string json = new string('[', 65) + new string(']', 65);
        var output = new ArrayBufferWriter<byte>();

        RedactionResult result = JsonBodyRedactor.Instance.Redact(
            new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(json)), output,
            Compile("""
                body:
                  - { path: "$.a", action: drop }
                """), Keys);

        Assert.Equal(RedactionStatus.MalformedInput, result.Status);
    }

    [Fact]
    public void Redact_MultiSegmentSequence_MatchesContiguousOutput()
    {
        const string yaml = """
            body:
              - { path: "$.card", action: hash }
            """;
        byte[] json = Encoding.UTF8.GetBytes("""{"card":"4111111111111111","keep":"yes"}""");

        (_, string contiguous) = Redact(yaml, Encoding.UTF8.GetString(json));

        var output = new ArrayBufferWriter<byte>();
        RedactionResult result = JsonBodyRedactor.Instance.Redact(
            Split(json, 7), output, Compile(yaml), Keys);

        Assert.Equal(RedactionStatus.Rewritten, result.Status);
        Assert.Equal(contiguous, Encoding.UTF8.GetString(output.WrittenSpan));
    }

    [Fact]
    public void Redact_RootScalarString_ScanUnknownApplies()
    {
        const string yaml = """
            freetext:
              scan_unknown: true
              detectors: [email]
            """;
        (_, string output) = Redact(yaml, "\"mail j@d.com\"");

        Assert.DoesNotContain("j@d.com", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_NoMatches_OutputSemanticallyIdentical()
    {
        const string yaml = """
            body:
              - { path: "$.nothing", action: drop }
            """;
        const string json = """{"a":[1,2.5,true,false,null,"s"],"b":{"c":"d \n e"}}""";
        (RedactionResult result, string output) = Redact(yaml, json);

        Assert.Equal(RedactionStatus.Rewritten, result.Status);
        Assert.Equal(0, result.ValuesRedacted);
        Assert.Equal("""{"a":[1,2.5,true,false,null,"s"],"b":{"c":"d \n e"}}""", output);
    }

    /// <summary>Splits a payload into a multi-segment ReadOnlySequence.</summary>
    private static ReadOnlySequence<byte> Split(byte[] payload, int chunk)
    {
        Segment? first = null;
        Segment? last = null;
        for (int offset = 0; offset < payload.Length; offset += chunk)
        {
            var memory = payload.AsMemory(offset, Math.Min(chunk, payload.Length - offset));
            var segment = new Segment(memory, offset);
            if (first is null)
            {
                first = segment;
            }
            else
            {
                last!.SetNext(segment);
            }

            last = segment;
        }

        return new ReadOnlySequence<byte>(first!, 0, last!, last!.Memory.Length);
    }

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public Segment(ReadOnlyMemory<byte> memory, long runningIndex)
        {
            Memory = memory;
            RunningIndex = runningIndex;
        }

        public void SetNext(Segment next) => Next = next;
    }
}
