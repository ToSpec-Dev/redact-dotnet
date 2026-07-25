using ToSpec.Redact;
using Xunit;

namespace ToSpec.Redact.Tests;

public sealed class RedactionRulesetCompilerTests
{
    // The §5.1 example, verbatim shape (wrapped in the spec's `redaction:` root).
    private const string SpecExampleYaml =
        """
        redaction:
          headers:
            strip:   [Authorization, X-Api-Key, Cookie, Proxy-Authorization]
            hash:    [X-Client-Id]
          body:
            - { path: "$.payment.cardNumber",  action: hash,  assertable: true }
            - { path: "$.guest.email",         action: mask,  keep: domain }
            - { path: "$.guest.phone",         action: drop }
            - { path: "$..password",           action: drop }
          freetext:
            fields: ["$.notes", "$.comments[*]"]
            scan_unknown: true
            detectors: [pan_luhn, email]
          defaults:
            unknown_pii_policy: detect_and_hash
        """;

    [Fact]
    public void Compile_SpecExample_ProducesExpectedModel()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(SpecExampleYaml);

        Assert.True(result.Success, string.Join("; ", result.Errors));
        CompiledRuleset ruleset = result.Ruleset!;

        Assert.Contains("authorization", (IReadOnlySet<string>)ruleset.Headers.Strip); // case-insensitive
        Assert.Contains("X-Client-Id", (IReadOnlySet<string>)ruleset.Headers.Hash);

        TrieNode card = ruleset.BodyRoot.Children["payment"].Children["cardNumber"];
        Assert.Equal(RedactionAction.Hash, card.Action);
        Assert.True(card.Assertable);

        TrieNode email = ruleset.BodyRoot.Children["guest"].Children["email"];
        Assert.Equal(RedactionAction.Mask, email.Action);
        Assert.Equal(MaskShape.Domain, email.Mask);

        TrieNode password = ruleset.BodyRoot.Descendant!.Children["password"];
        Assert.True(ruleset.BodyRoot.Descendant.IsDescendant);
        Assert.Equal(RedactionAction.Drop, password.Action);

        Assert.True(ruleset.BodyRoot.Children["notes"].IsFreetext);
        Assert.True(ruleset.BodyRoot.Children["comments"].AnyIndex!.IsFreetext);
        Assert.True(ruleset.Freetext.ScanUnknown);
        Assert.Equal(UnknownPiiPolicy.DetectAndHash, ruleset.UnknownPiiPolicy);
        Assert.True(ruleset.HasBodyRules);
    }

    [Fact]
    public void Compile_BareDocumentWithoutRedactionRoot_Accepted()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(
            """
            headers:
              strip: [Authorization]
            """);

        Assert.True(result.Success, string.Join("; ", result.Errors));
        Assert.False(result.Ruleset!.HasBodyRules);
    }

    [Fact]
    public void Compile_FilterExpressionPath_FailsNamingSupportedSubset()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(
            """
            body:
              - { path: "$.items[?(@.price)]", action: drop }
            """);

        RulesetCompileError error = Assert.Single(result.Errors);
        Assert.Equal("body[0].path", error.Location);
        Assert.Contains("filter expressions are not supported", error.Message, StringComparison.Ordinal);
        Assert.Contains("recursive descent", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Compile_UnknownAction_FailsListingSupportedActions()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(
            """
            body:
              - { path: "$.a", action: obliterate }
            """);

        RulesetCompileError error = Assert.Single(result.Errors);
        Assert.Contains("drop, mask, hash, tokenize_typed", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Compile_UnknownDetector_FailsListingAvailable()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(
            """
            freetext:
              fields: ["$.notes"]
              detectors: [pan_luhn, iban]
            """);

        RulesetCompileError error = Assert.Single(result.Errors);
        Assert.Equal("freetext.detectors[1]", error.Location);
        Assert.Contains("Available detectors: pan_luhn, email", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Compile_FreetextWithoutDetectors_Fails()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(
            """
            freetext:
              scan_unknown: true
            """);

        RulesetCompileError error = Assert.Single(result.Errors);
        Assert.Contains("no detectors are listed", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Compile_DuplicateExactPath_Fails()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(
            """
            body:
              - { path: "$.a.b", action: drop }
              - { path: "$.a.b", action: hash }
            """);

        RulesetCompileError error = Assert.Single(result.Errors);
        Assert.Equal("body[1].path", error.Location);
        Assert.Contains("duplicate rule", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Compile_KeepOnNonMask_Fails()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(
            """
            body:
              - { path: "$.a", action: drop, keep: last4 }
            """);

        RulesetCompileError error = Assert.Single(result.Errors);
        Assert.Contains("keep only applies to action: mask", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Compile_AssertableOnDrop_Fails()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(
            """
            body:
              - { path: "$.a", action: drop, assertable: true }
            """);

        RulesetCompileError error = Assert.Single(result.Errors);
        Assert.Contains("value-preserving action", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Compile_BodyAsMappingNotSequence_Fails()
    {
        // body: is a single mapping rather than a sequence of rules — the intended
        // rule must be rejected, not silently ignored (which would disable redaction).
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(
            """
            body:
              path: "$.card"
              action: hash
            """);

        Assert.False(result.Success);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void Compile_ErrorsAreCollected_NotFailFast()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(
            """
            body:
              - { path: "$.items[0]", action: drop }
              - { path: "$.b", action: shred }
            freetext:
              detectors: [jwt]
            defaults:
              unknown_pii_policy: nuke
            """);

        Assert.False(result.Success);
        Assert.Equal(4, result.Errors.Count);
    }

    [Fact]
    public void Compile_UnknownTopLevelKey_FailsWithYamlLocation()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(
            """
            headerz:
              strip: [Authorization]
            """);

        RulesetCompileError error = Assert.Single(result.Errors);
        Assert.Contains("headerz", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Compile_EmptyDocument_Fails()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile("   ");
        RulesetCompileError error = Assert.Single(result.Errors);
        Assert.Contains("empty", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Compile_TokenizeTyped_CompilesWithFlagRecorded()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(
            """
            body:
              - { path: "$.rate.amount", action: tokenize_typed, assertable: true }
            """);

        Assert.True(result.Success, string.Join("; ", result.Errors));
        TrieNode node = result.Ruleset!.BodyRoot.Children["rate"].Children["amount"];
        Assert.Equal(RedactionAction.TokenizeTyped, node.Action);
        Assert.True(node.Assertable);
    }
}
