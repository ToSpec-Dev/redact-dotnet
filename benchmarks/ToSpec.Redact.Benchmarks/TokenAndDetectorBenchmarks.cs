using System.Collections.Frozen;
using System.Text;
using BenchmarkDotNet.Attributes;
using ToSpec.Redact;

namespace ToSpec.Redact.Benchmarks;

[MemoryDiagnoser]
public class TokenAndDetectorBenchmarks
{
    private readonly RedactionKeyring _keys = new(new byte[32], hmacKeyVersion: 12);
    private readonly FrozenSet<DetectorKind> _bothDetectors =
        new[] { DetectorKind.PanLuhn, DetectorKind.Email }.ToFrozenSet();
    private readonly FrozenSet<DetectorKind> _panDetector =
        new[] { DetectorKind.PanLuhn }.ToFrozenSet();
    private readonly byte[] _utf8 = Encoding.UTF8.GetBytes("4111111111111111");
    private int _hits;

    [Benchmark(Baseline = true)]
    public string TokenizeBytes() => HmacTokenizer.Tokenize(_utf8, _keys);

    [Benchmark]
    public string TokenizeChars() => HmacTokenizer.Tokenize("4111111111111111".AsSpan(), _keys);

    [Benchmark]
    public string? DetectorSinglePanHit()
    {
        _hits = 0;
        return Detectors.Scan(
            "charge card 4111111111111111 today",
            _panDetector,
            hashReplacement: false,
            _keys,
            ref _hits);
    }

    [Benchmark]
    public string? DetectorPanAndEmailHits()
    {
        _hits = 0;
        return Detectors.Scan(
            "charge card 4111111111111111 and email ada.lovelace@example.com today",
            _bothDetectors,
            hashReplacement: true,
            _keys,
            ref _hits);
    }
}
