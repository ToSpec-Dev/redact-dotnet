using BenchmarkDotNet.Running;

BenchmarkSwitcher.FromAssembly(typeof(ToSpec.Redact.Benchmarks.JsonRedactorBenchmarks).Assembly).Run(args);
