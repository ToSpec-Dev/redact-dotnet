# ToSpec.Redact

**A structured-first redaction engine for JSON and XML request/response bodies.**
Streaming path-trie redaction with deterministic HMAC tokenization, shape-preserving
masking, and a Luhn-validated PAN / PII detector layer. Zero platform dependencies —
pure CPU over pooled buffers, one runtime dependency (YamlDotNet).

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

This is the engine behind the [ToSpec](https://tospec.dev) certification platform. It
runs at two enforcement points from the **same compiled ruleset**: the capture gateway
(server side) and inside a provider's own process via the ToSpec SDK (so sensitive values
are redacted *before* they ever leave provider infrastructure). This package is that
engine, extracted and open-sourced.

## Why structured-first?

Request/response bodies are JSON or XML the overwhelming majority of the time. Treating
them as *structures* rather than strings means redaction is a single streaming rewrite
(`Utf8JsonReader` → `Utf8JsonWriter`) driven by a path-trie compiled from your rules — no
DOM, no full-buffer regex scan on the common path. Regex is the *fallback* layer for
free-text fields, and even there PAN candidates are Luhn-validated in code to kill false
positives.

## Install

```sh
dotnet add package ToSpec.Redact
```

## Quick start

Rules are authored in YAML and compiled once; the compiled ruleset is then applied to
each body over pooled buffers.

```csharp
using System.Buffers;
using System.Text;
using ToSpec.Redact;

// 1. Compile a ruleset (do this once, cache the result).
RulesetCompileResult compiled = RedactionRulesetCompiler.Compile("""
    body:
      - { path: "$.payment.cardNumber", action: hash }   # deterministic token
      - { path: "$.guest.email",        action: mask, keep: domain }
      - { path: "$..password",          action: drop }
    freetext:
      scan_unknown: true
      detectors: [pan_luhn, email]
    defaults:
      unknown_pii_policy: detect_and_hash
    """);

CompiledRuleset ruleset = compiled.Ruleset!;   // check compiled.Errors in real code

// 2. A per-tenant HMAC keyring drives deterministic tokenization.
var keys = new RedactionKeyring(hmacKey: myKeyBytes, hmacKeyVersion: 1);

// 3. Redact a body. The engine is stateless and thread-safe; reuse the singleton.
var input = new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(json));
var output = new ArrayBufferWriter<byte>();
RedactionResult result = JsonBodyRedactor.Instance.Redact(input, output, ruleset, keys);

if (result.Status == RedactionStatus.Rewritten)
{
    string redacted = Encoding.UTF8.GetString(output.WrittenSpan);
    // "$.payment.cardNumber" is now "tsr_v1_<base32>", email masked, passwords dropped.
}
```

XML bodies use `XmlBodyRedactor.Instance` with the same ruleset and API;
`BodyRedactorRegistry.Resolve(contentFormat)` picks the right redactor by format.

## Actions

| Action           | Effect |
|------------------|--------|
| `drop`           | Remove the value entirely. |
| `mask`           | Shape-preserving mask (`j***@d***.com`, last-4). `keep: domain` / `keep: last4`. |
| `hash`           | Deterministic `HMAC-SHA-256` → `tsr_v{ver}_{base32}` token. Same input ⇒ same token, so equality assertions and cross-request joins survive redaction. |
| `tokenize_typed` | Hash plus a typed shadow value retained only in evaluator memory; never persisted. |

Paths use a JSONPath subset (child, recursive descent `..`, wildcard index `[*]`) chosen
to be compilable into the streaming trie. Free-text detectors: `pan_luhn`, `email`.

## The guarantee

Values fed to the engine **never survive into its output buffer**. A Luhn-valid PAN, an
email, and auth-shaped secrets come out tokenized, masked, or dropped — the raw bytes are
absent. This is enforced structurally (see `RedactionGuaranteeTests`) and holds even when
no path rule targets the value, via the free-text detector layer. A redactor never throws
on bad input: malformed bodies return `RedactionStatus.MalformedInput` and the caller
owns the drop-or-persist decision.

## Performance

Target: **≥ 200 MB/s per core** on typical JSON, **< 1 ms p99** for bodies ≤ 64 KB.
Measured with the `benchmarks/` harness (BenchmarkDotNet); run it yourself with:

```sh
dotnet run -c Release --project benchmarks/ToSpec.Redact.Benchmarks -- --filter '*'
```

Three ruleset shapes are measured across payload sizes: **NoMatch** (pure traversal
cost), **Typical** (5 rules including a recursive-descent `$..password` and a
`$.items[*].ratePlan` hash that matches every array element — a deliberately
hash-heavy shape), and **ScanHeavy** (every string swept through both detectors).
The goal is efficiency, not just peak throughput: targeted path rules should stay near
pure traversal cost, while `scan_unknown` is the higher-CPU safety net for values that
cannot be addressed by path.

`BenchmarkDotNet v0.15.4 · macOS 26.5 · Apple M3 Max (14 cores) · .NET SDK 10.0.100 ·
ShortRun (3 iterations)`. Throughput is `PayloadBytes / Mean` (1 MB = 1,048,576 B),
single-threaded. Reproduce with the command above (drop `--job short` for a full run).

| Ruleset   | Payload | Mean      | Throughput | Allocated |
|-----------|--------:|----------:|-----------:|----------:|
| NoMatch   |   1 KB  |   2.00 µs |  ~488 MB/s |     216 B |
| NoMatch   |   8 KB  |  14.37 µs |  ~543 MB/s |     216 B |
| NoMatch   |  64 KB  | 115.86 µs |  ~539 MB/s |     216 B |
| NoMatch   |   1 MB  |   1.822 ms |  ~549 MB/s |    216 B |
| Typical   |   1 KB  |   6.02 µs |  ~162 MB/s |   3.0 KB  |
| Typical   |   8 KB  |  52.87 µs |  ~148 MB/s |  26.4 KB  |
| Typical   |  64 KB  | 412.60 µs |  ~152 MB/s | 212.8 KB  |
| Typical   |   1 MB  |   6.223 ms |  ~161 MB/s |   3.3 MB  |
| ScanHeavy |   1 KB  |   3.39 µs |  ~288 MB/s |   2.0 KB  |
| ScanHeavy |   8 KB  |  19.45 µs |  ~402 MB/s |   2.0 KB  |
| ScanHeavy |  64 KB  | 150.08 µs |  ~417 MB/s |   2.0 KB  |
| ScanHeavy |   1 MB  |   2.367 ms |  ~423 MB/s |   2.0 KB  |

XML streaming-path check after the 1.0.2 encoding-detection change:

| Ruleset   | Payload | Mean      | Throughput | Allocated |
|-----------|--------:|----------:|-----------:|----------:|
| Typical   |   1 KB  |   7.50 µs |  ~130 MB/s |  18.8 KB  |
| Typical   |   8 KB  |  57.20 µs |  ~137 MB/s |  64.6 KB  |
| Typical   |  64 KB  | 445.67 µs |  ~140 MB/s | 357.2 KB  |
| ScanHeavy |   1 KB  |   5.62 µs |  ~174 MB/s |  15.9 KB  |
| ScanHeavy |   8 KB  |  31.95 µs |  ~244 MB/s |  35.2 KB  |
| ScanHeavy |  64 KB  | 236.31 µs |  ~264 MB/s | 119.1 KB  |

**Reading the numbers.** BenchmarkDotNet's `Mean` is the single-threaded CPU-time proxy
for this synchronous redaction work; `Allocated` and GC columns show whether a speedup is
buying throughput by increasing host memory pressure. The **< 1 ms p99 for bodies ≤ 64 KB**
target holds for every
shape (the worst ≤64 KB case, hash-heavy Typical at 64 KB, is 0.41 ms). Pure traversal
and detector-scan throughput clear **200 MB/s per core** comfortably (~420–550 MB/s).
The Typical shape was allocation-bound at ~150 MB/s because it hashed every element
of the grown `items[]` array into a fresh token string. **1.1.0 removed that cost**
(`HmacTokenizer.TokenizeTo` span emission + per-thread keyed-HMAC reuse): measured on a
server-class AMD EPYC-Rome core (ShortRun, 2026-08-03), Typical went from 27.4 ms /
1.24 MB allocated per 1 MB payload to **14.1 ms / 264 B** (1.9x, allocations flat), and
ScanHeavy gained ~1.4x from the HMAC reuse alone. Typical is now compute-bound (trie
descent + HMAC) at ~74 MB/s on that core — still short of the 200 MB/s target on server
hardware, which the platform's sizing (SPEC-infrastructure §2.4) should assume until the
traversal cost is next attacked. The Apple-Silicon table above predates 1.1.0. These are
`ShortRun` numbers, not a tuned server measurement; treat them as a floor.
The engine does not start worker threads or move redaction to background CPU; callers who
need to keep request handling isolated should run it on their existing forwarding path
and size that path from the `Mean`/allocation numbers above.

## Building from source

```sh
dotnet build -warnaserror
dotnet test
```

Requires the .NET 10 SDK (pinned in `global.json`).

## Reproducible releases

Release packages are **reproducible**: packing a given tag produces a byte-identical
`lib/net10.0/ToSpec.Redact.dll` regardless of where the repository is checked out. That
matters for a redaction engine — if you cannot rebuild the binary you were handed, you
cannot confirm it is the code you are reading.

Two properties make it work:

- `ContinuousIntegrationBuild` on Release normalizes embedded source paths. Without it a
  build is deterministic but *not* reproducible: identical in place, different from any
  other directory — so a verifier gets a mismatch and cannot tell "built elsewhere" from
  "built from something else".
- Packing refuses a dirty worktree (`scripts/ensure-clean-pack.sh`), because the nuspec
  stamps a commit id and a dirty pack would name sources it was not built from.

To verify a package you have:

```sh
git checkout vX.Y.Z
dotnet pack src/ToSpec.Redact/ToSpec.Redact.csproj -c Release -o /tmp/out
unzip -p /tmp/out/ToSpec.Redact.X.Y.Z.nupkg 'lib/net10.0/ToSpec.Redact.dll' | sha256sum
```

Compare against the sha256 recorded in the annotated tag (`git tag -n99 vX.Y.Z`). Compare
the **assembly**, not the `.nupkg` — zip entry timestamps differ between packs, so the
archive is never byte-stable even when the build is.

The tag carries that hash rather than the release commit message, and that is forced
rather than stylistic: SourceLink embeds the commit id in the binary, so the assembly's
hash depends on the commit message. A commit cannot state the hash of an artifact whose
inputs include that commit.

## License

[Apache-2.0](LICENSE).
