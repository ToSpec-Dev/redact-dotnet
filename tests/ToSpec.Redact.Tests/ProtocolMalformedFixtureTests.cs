using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace ToSpec.Redact.Tests;

public sealed class ProtocolMalformedFixtureTests
{
    [Fact]
    public void CanonicalBinaryMalformedVectors_AreRejected()
    {
        string path = Path.Combine(SiblingProtocolRoot(), "fixtures", "malformed.json");
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(path));
        RulesetCompileResult compiled = RedactionRulesetCompiler.Compile("body: []\n");
        Assert.True(compiled.Success);
        var keys = new RedactionKeyring(new byte[32], 1);

        foreach (JsonElement vector in document.RootElement.GetProperty("vectors").EnumerateArray())
        {
            string format = vector.GetProperty("content_format").GetString()!;
            byte[] body = Convert.FromBase64String(vector.GetProperty("body_base64").GetString()!);
            IBodyRedactor redactor = BodyRedactorRegistry.Resolve(format)!;
            var output = new ArrayBufferWriter<byte>();
            RedactionResult result = redactor.Redact(
                new ReadOnlySequence<byte>(body), output, compiled.Ruleset!, keys);
            Assert.True(
                result.Status == RedactionStatus.MalformedInput,
                $"{vector.GetProperty("name").GetString()}: expected malformed, got {result.Status}");
        }
    }

    [Fact]
    public void CanonicalGeneratedEdgeCases_EnforceResourceAndNamespaceBounds()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(SiblingProtocolRoot(), "fixtures", "edge-cases.json")));
        JsonElement root = document.RootElement;
        int maxDepth = root.GetProperty("max_depth").GetInt32();
        RulesetCompileResult compiled = RedactionRulesetCompiler.Compile("body: []\n");
        var keys = new RedactionKeyring(new byte[32], 1);

        foreach (string format in new[] { "json", "xml" })
        {
            static string Nested(string kind, int depth) => kind == "json"
                ? new string('[', depth) + "0" + new string(']', depth)
                : string.Concat(Enumerable.Repeat("<n>", depth)) + "x"
                    + string.Concat(Enumerable.Repeat("</n>", depth));
            IBodyRedactor redactor = BodyRedactorRegistry.Resolve(format)!;
            RedactionResult At(int depth) => redactor.Redact(
                new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(Nested(format, depth))),
                new ArrayBufferWriter<byte>(), compiled.Ruleset!, keys);
            Assert.Equal(RedactionStatus.Rewritten, At(maxDepth).Status);
            Assert.Equal(RedactionStatus.MalformedInput, At(maxDepth + 1).Status);
        }

        JsonElement ns = root.GetProperty("namespace_collision");
        var output = new ArrayBufferWriter<byte>();
        RedactionResult xml = XmlBodyRedactor.Instance.Redact(
            new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(ns.GetProperty("body").GetString()!)),
            output, compiled.Ruleset!, keys);
        Assert.Equal(RedactionStatus.Rewritten, xml.Status);
        Assert.Contains(ns.GetProperty("must_preserve").GetString()!, Encoding.UTF8.GetString(output.WrittenSpan));

        JsonElement hostile = root.GetProperty("adversarial_email");
        string text = string.Concat(Enumerable.Repeat(
            hostile.GetProperty("unit").GetString()!, hostile.GetProperty("repeat").GetInt32()))
            + hostile.GetProperty("suffix").GetString();
        int hits = 0;
        var watch = Stopwatch.StartNew();
        Assert.Null(Detectors.Scan(text, new[] { DetectorKind.Email }.ToFrozenSet(), false, keys, ref hits));
        watch.Stop();
        Assert.True(watch.ElapsedMilliseconds < hostile.GetProperty("max_milliseconds").GetInt32(),
            $"adversarial detector case took {watch.ElapsedMilliseconds}ms");
    }

    private static string SiblingProtocolRoot()
    {
        if (Environment.GetEnvironmentVariable("TOSPEC_PROTOCOL_ROOT") is { Length: > 0 } configured)
        {
            return configured;
        }
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && directory.Name != "redact-dotnet")
        {
            directory = directory.Parent;
        }
        return Path.Combine(directory?.Parent?.FullName
            ?? throw new DirectoryNotFoundException("redact-dotnet repository root not found"), "sdk-protocol");
    }
}
