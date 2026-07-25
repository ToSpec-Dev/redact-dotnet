using System.Security.Cryptography;
using System.Text;
using ToSpec.Redact;
using Xunit;

namespace ToSpec.Redact.Tests;

public sealed class HmacTokenizerTests
{
    [Fact]
    public void Tokenize_KnownInput_MatchesManuallyComputedToken()
    {
        var key = new byte[32];
        key[0] = 0x42;
        var keyring = new RedactionKeyring(key, hmacKeyVersion: 3);

        string token = HmacTokenizer.Tokenize("4111111111111111".AsSpan(), keyring);

        byte[] digest = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes("4111111111111111"));
        Assert.Equal($"tsr_v3_{Base32.Encode(digest)}", token);
        Assert.Equal("tsr_v3_".Length + 52, token.Length); // full 32-byte digest → 52 chars
    }

    [Fact]
    public void Tokenize_CharAndByteOverloads_Agree()
    {
        var keyring = new RedactionKeyring(RandomNumberGenerator.GetBytes(32), hmacKeyVersion: 1);

        Assert.Equal(
            HmacTokenizer.Tokenize("héllo".AsSpan(), keyring),
            HmacTokenizer.Tokenize(Encoding.UTF8.GetBytes("héllo"), keyring));
    }

    [Fact]
    public void Tokenize_DifferentKeyVersions_DifferentTokens()
    {
        var v1 = new RedactionKeyring(RandomNumberGenerator.GetBytes(32), hmacKeyVersion: 1);
        var v2 = new RedactionKeyring(RandomNumberGenerator.GetBytes(32), hmacKeyVersion: 2);

        string first = HmacTokenizer.Tokenize("value".AsSpan(), v1);
        string second = HmacTokenizer.Tokenize("value".AsSpan(), v2);

        Assert.NotEqual(first, second);
        Assert.StartsWith("tsr_v1_", first, StringComparison.Ordinal);
        Assert.StartsWith("tsr_v2_", second, StringComparison.Ordinal);
    }
}
