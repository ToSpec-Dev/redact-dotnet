using System.Text.Json;
using ToSpec.Redact;
using Xunit;

namespace ToSpec.Redact.Tests;

public sealed class CompiledRulesetSerializerTests
{
    private const string Yaml =
        """
        headers:
          strip: [Cookie, Authorization]
          hash: [X-Client-Id]
        body:
          - { path: "$.payment.cardNumber", action: hash, assertable: true }
          - { path: "$.guest.email", action: mask, keep: domain }
          - { path: "$..password", action: drop }
          - { path: "$.items[*].price", action: tokenize_typed }
        freetext:
          fields: ["$.notes"]
          scan_unknown: true
          detectors: [email, pan_luhn]
        """;

    private static CompiledRuleset Compile()
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(Yaml);
        Assert.True(result.Success, string.Join("; ", result.Errors));
        return result.Ruleset!;
    }

    [Fact]
    public void SerializeDeserialize_RoundTripsStructure()
    {
        CompiledRuleset original = Compile();
        CompiledRuleset restored = CompiledRulesetSerializer.Deserialize(
            CompiledRulesetSerializer.Serialize(original));

        Assert.Contains("authorization", (IReadOnlySet<string>)restored.Headers.Strip);
        Assert.Contains("x-client-id", (IReadOnlySet<string>)restored.Headers.Hash);

        TrieNode card = restored.BodyRoot.Children["payment"].Children["cardNumber"];
        Assert.Equal(RedactionAction.Hash, card.Action);
        Assert.True(card.Assertable);

        Assert.Equal(MaskShape.Domain, restored.BodyRoot.Children["guest"].Children["email"].Mask);
        Assert.True(restored.BodyRoot.Descendant!.IsDescendant);
        Assert.Equal(RedactionAction.Drop, restored.BodyRoot.Descendant.Children["password"].Action);
        Assert.Equal(
            RedactionAction.TokenizeTyped,
            restored.BodyRoot.Children["items"].AnyIndex!.Children["price"].Action);
        Assert.True(restored.BodyRoot.Children["notes"].IsFreetext);
        Assert.True(restored.Freetext.ScanUnknown);
        Assert.Equal(2, restored.Freetext.Detectors.Count);
        Assert.Equal(UnknownPiiPolicy.DetectAndHash, restored.UnknownPiiPolicy);
    }

    [Fact]
    public void Serialize_SameYamlTwice_ByteStable()
    {
        // Publish-time determinism: identical YAML → identical jsonb, so config
        // diffs are meaningful and re-publishes are detectable as no-ops.
        string first = CompiledRulesetSerializer.Serialize(Compile());
        string second = CompiledRulesetSerializer.Serialize(Compile());

        Assert.Equal(first, second);
        Assert.Contains("\"schema\":1", first, StringComparison.Ordinal);
    }

    [Fact]
    public void Deserialize_UnknownSchemaVersion_Rejected()
    {
        string json = CompiledRulesetSerializer.Serialize(Compile())
            .Replace("\"schema\":1", "\"schema\":99", StringComparison.Ordinal);

        JsonException exception = Assert.Throws<JsonException>(
            () => CompiledRulesetSerializer.Deserialize(json));
        Assert.Contains("schema 99", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Deserialize_MalformedJson_Throws() =>
        Assert.ThrowsAny<JsonException>(() => CompiledRulesetSerializer.Deserialize("{not json"));
}
