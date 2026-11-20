# AGENTS.md — repo conventions for ToSpec.Redact

`ToSpec.Redact` is the **structured-first request/response redaction engine** used by
the ToSpec certification platform at two enforcement points: the capture gateway (cert
path) and inside a provider's own process via the ToSpec SDK (prod path) — "same rule
format, two enforcement points." This repo is the public, Apache-2.0 home of that engine.
It was extracted from the platform monorepo; the platform now consumes it as a package.

## The one rule that governs this repo

**Zero platform dependencies.** This package is pure CPU over pooled buffers plus one
runtime dependency: **YamlDotNet** (the ruleset source format is YAML; .NET ships no
YAML parser). No Npgsql, no ASP.NET, no logging framework, no I/O, no `ToSpec.Core`.
If a change would pull in a platform or I/O dependency, stop — it belongs in a consumer,
not here. The engine takes everything it needs (the compiled ruleset, the HMAC keyring)
as parameters; it resolves nothing itself.

## Design principles (from SPEC-cert-gateway-architecture §5)

- **Structured-first, regex-last.** Bodies are JSON or XML 95%+ of the time; treat them
  as structures, not strings. The structured pass is a single streaming rewrite
  (`Utf8JsonReader`/`Utf8JsonWriter`, `XmlReader`/`XmlWriter`) over pooled UTF-8 buffers
  — one pass, no DOM for the common case. Rules compile at publish time into a path-trie
  walked during the stream.
- **Regex is the fallback layer only.** `.NET` source-generated regexes, RE2-style
  discipline (no backtracking); PAN candidates get Luhn-validated in code to kill false
  positives. Detectors live in `Detectors.cs`.
- **Actions:** `drop`, `mask` (shape-preserving), `hash` (HMAC-SHA-256, per-tenant key,
  deterministic base32 token so equality assertions and cross-request joins survive),
  `tokenize_typed`.
- **A redactor never throws on bad input.** Malformed bodies return
  `RedactionStatus.MalformedInput`; the caller owns the safety policy (the gateway drops
  the body rather than persist unredacted bytes).

## Stack rules (non-negotiable)

- **.NET 10**, C# only. `net10.0`, pinned by `global.json`.
- **No new NuGet dependencies** without listing each one and why in the PR. Versions are
  centrally managed in `Directory.Packages.props` — add the `PackageVersion` there and a
  bare `PackageReference` in the project. The runtime library's dependency budget is
  **one** (YamlDotNet); guard it.
- **Warnings are errors** — repo-wide via `Directory.Build.props`
  (`TreatWarningsAsErrors` + analyzers at `latest-recommended` + `EnforceCodeStyleInBuild`).
  Fix the warning; never suppress without a comment and review sign-off.
- **Performance is a feature.** The throughput target is ≥ 200 MB/s per core on typical
  JSON and < 1 ms p99 for bodies ≤ 64 KB (SPEC §5.2). Prefer spans, pooled buffers, and
  frozen collections; avoid allocation on the hot path. The benchmark harness
  (`benchmarks/`) is the evidence — re-run it and update the README table when you touch
  the streaming path.

## Public API stability

This is a published package with external consumers (the ToSpec SDKs and third parties).
**Never change a public signature or a token/serialization format without a version
bump.** The compiled-ruleset serialization (`CompiledRulesetSerializer`, `CurrentSchema`)
and the token format (`tsr_v{ver}_{base32}`) are wire contracts — additive changes only,
schema-versioned.

## Repo layout

```
src/ToSpec.Redact/                  the engine (one assembly, PackageId ToSpec.Redact)
tests/ToSpec.Redact.Tests/          xunit v3 unit tests + the structural guarantee test
benchmarks/ToSpec.Redact.Benchmarks/ BenchmarkDotNet throughput harness
```

## Testing

- Framework **xunit v3**. Naming `MethodOrBehavior_Condition_ExpectedOutcome`; test
  classes `<TypeUnderTest>Tests`.
- **The structural guarantee is a test, always.** `RedactionGuaranteeTests` proves a
  Luhn PAN, an email, and auth-shaped secrets fed to the engine never survive into its
  output buffer. It has no DB and no platform code — it is the standalone twin of the
  platform's gateway-side raw-column-scan test. Keep it green; extend it when you add a
  detector or action.
- No live external calls, ever (there are none to make — the engine is pure).

## Build / run

```sh
dotnet build -warnaserror
dotnet test
dotnet run -c Release --project benchmarks/ToSpec.Redact.Benchmarks -- --filter '*'
```
