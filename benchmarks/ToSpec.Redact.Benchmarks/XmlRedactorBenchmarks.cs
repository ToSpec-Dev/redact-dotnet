using System.Buffers;
using System.Text;
using BenchmarkDotNet.Attributes;
using ToSpec.Redact;

namespace ToSpec.Redact.Benchmarks;

[MemoryDiagnoser]
public class XmlRedactorBenchmarks
{
    private const string TypicalYaml =
        """
        body:
          - { path: "$.payment.cardNumber", action: hash }
          - { path: "$.guest.email", action: mask, keep: domain }
          - { path: "$.guest.phone", action: drop }
          - { path: "$..password", action: drop }
          - { path: "$.items[*].ratePlan", action: hash }
        """;

    private const string ScanHeavyYaml =
        """
        freetext:
          scan_unknown: true
          detectors: [pan_luhn, email]
        defaults:
          unknown_pii_policy: detect_and_hash
        """;

    private readonly RedactionKeyring _keys = new(new byte[32], hmacKeyVersion: 1);

    private CompiledRuleset _typical = null!;
    private CompiledRuleset _scanHeavy = null!;
    private ReadOnlySequence<byte> _payload;
    private ArrayBufferWriter<byte> _output = null!;

    [Params(1_024, 8_192, 65_536)]
    public int PayloadBytes { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _typical = Compile(TypicalYaml);
        _scanHeavy = Compile(ScanHeavyYaml);
        _payload = new ReadOnlySequence<byte>(BuildBookingXml(PayloadBytes));
        _output = new ArrayBufferWriter<byte>(PayloadBytes + 1024);
    }

    [Benchmark(Baseline = true)]
    public RedactionResult Typical() => Run(_typical);

    [Benchmark]
    public RedactionResult ScanHeavy() => Run(_scanHeavy);

    private RedactionResult Run(CompiledRuleset rules)
    {
        _output.ResetWrittenCount();
        return XmlBodyRedactor.Instance.Redact(_payload, _output, rules, _keys);
    }

    private static CompiledRuleset Compile(string yaml)
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(yaml);
        return result.Ruleset ?? throw new InvalidOperationException(string.Join("; ", result.Errors));
    }

    private static byte[] BuildBookingXml(int targetBytes)
    {
        var xml = new StringBuilder(targetBytes + 512);
        xml.Append(
            """
            <booking><reservationId>res-84213</reservationId><payment><cardNumber>4111111111111111</cardNumber><expiry>12/28</expiry></payment>
            <guest><email>ada.lovelace@example.com</email><phone>+1 555 0100</phone><name>Ada Lovelace</name><password>hunter2</password></guest>
            <notes>guest called from +1 555 0100 about card ending 1111</notes><items>
            """.Replace("\n", string.Empty, StringComparison.Ordinal));

        int index = 0;
        while (xml.Length < targetBytes - 128)
        {
            xml.Append(
                $$"""<item><night>2026-07-{{(index % 28) + 1:00}}</night><ratePlan>BAR-{{index}}</ratePlan><amount>{{100 + (index % 90)}}.50</amount><available>{{(index % 2 == 0 ? "true" : "false")}}</available><comment>row {{index}} nothing sensitive here</comment></item>""");
            index++;
        }

        xml.Append("</items></booking>");
        return Encoding.UTF8.GetBytes(xml.ToString());
    }
}
