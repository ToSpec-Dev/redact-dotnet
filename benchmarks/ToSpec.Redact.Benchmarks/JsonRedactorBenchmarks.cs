using System.Buffers;
using System.Text;
using BenchmarkDotNet.Attributes;
using ToSpec.Redact;

namespace ToSpec.Redact.Benchmarks;

/// <summary>
/// Streaming JSON redactor throughput (SPEC-cert-gateway-architecture §5.2 target:
/// ≥ 200 MB/s per core on typical JSON; &lt; 1 ms p99 for bodies ≤ 64 KB). MB/s =
/// PayloadBytes / mean-time; computed per row and recorded in the repo README.
/// Three ruleset shapes: NoMatch (pure traversal cost),
/// Typical (5 rules incl. recursive descent — the expected production shape),
/// ScanHeavy (scan_unknown sweeping every string through both detectors).
/// </summary>
[MemoryDiagnoser]
public class JsonRedactorBenchmarks
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

    private const string NoMatchYaml =
        """
        body:
          - { path: "$.never.matches.anything", action: drop }
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

    private CompiledRuleset _noMatch = null!;
    private CompiledRuleset _typical = null!;
    private CompiledRuleset _scanHeavy = null!;
    private ReadOnlySequence<byte> _payload;
    private ArrayBufferWriter<byte> _output = null!;

    [Params(1_024, 8_192, 65_536, 1_048_576)]
    public int PayloadBytes { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _noMatch = Compile(NoMatchYaml);
        _typical = Compile(TypicalYaml);
        _scanHeavy = Compile(ScanHeavyYaml);
        _payload = new ReadOnlySequence<byte>(BuildBookingJson(PayloadBytes));
        _output = new ArrayBufferWriter<byte>(PayloadBytes + 1024);
    }

    [Benchmark(Baseline = true)]
    public RedactionResult NoMatch() => Run(_noMatch);

    [Benchmark]
    public RedactionResult Typical() => Run(_typical);

    [Benchmark]
    public RedactionResult ScanHeavy() => Run(_scanHeavy);

    private RedactionResult Run(CompiledRuleset rules)
    {
        _output.ResetWrittenCount();
        return JsonBodyRedactor.Instance.Redact(_payload, _output, rules, _keys);
    }

    private static CompiledRuleset Compile(string yaml)
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(yaml);
        return result.Ruleset ?? throw new InvalidOperationException(string.Join("; ", result.Errors));
    }

    /// <summary>A booking-shaped document grown to ~<paramref name="targetBytes"/> via its items array.</summary>
    private static byte[] BuildBookingJson(int targetBytes)
    {
        var json = new StringBuilder(targetBytes + 512);
        json.Append(
            """
            {"reservationId":"res-84213","payment":{"cardNumber":"4111111111111111","expiry":"12/28"},
            "guest":{"email":"ada.lovelace@example.com","phone":"+1 555 0100","name":"Ada Lovelace","password":"hunter2"},
            "notes":"guest called from +1 555 0100 about card ending 1111","items":[
            """.Replace("\n", string.Empty, StringComparison.Ordinal));

        int index = 0;
        while (json.Length < targetBytes - 128)
        {
            if (index > 0)
            {
                json.Append(',');
            }

            json.Append(
                $$"""{"night":"2026-07-{{(index % 28) + 1:00}}","ratePlan":"BAR-{{index}}","amount":{{100 + (index % 90)}}.50,"available":{{(index % 2 == 0 ? "true" : "false")}},"comment":"row {{index}} nothing sensitive here"}""");
            index++;
        }

        json.Append("]}");
        return Encoding.UTF8.GetBytes(json.ToString());
    }
}
