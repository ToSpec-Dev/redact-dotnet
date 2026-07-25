using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace ToSpec.Redact;

/// <summary>
/// Deterministic tokenization (SPEC-cert-gateway-architecture §5.2 "hash"):
/// <c>tsr_v{keyVersion}_{base32(HMAC-SHA-256(key, value))}</c> — full 32-byte
/// digest, 52 lowercase base32 chars. Same tenant + key version + value ⇒ same
/// token, so equality assertions and cross-request joins survive redaction.
/// Numbers are tokenized over their literal JSON text (<c>1.50</c> ≠ <c>1.5</c>);
/// suites asserting on hashed numeric fields must assert the exact literal.
/// </summary>
public static class HmacTokenizer
{
    private const string TokenPrefix = "tsr_v";
    private const int DigestBase32Length = 52;
    private const int StackUtf8Bytes = 1024;

    public static string Tokenize(ReadOnlySpan<byte> valueUtf8, RedactionKeyring keys)
    {
        ArgumentNullException.ThrowIfNull(keys);

        Span<byte> digest = stackalloc byte[HMACSHA256.HashSizeInBytes];
        HMACSHA256.HashData(keys.HmacKey, valueUtf8, digest);

        int versionDigits = CountDigits(keys.HmacKeyVersion);
        Span<char> token = stackalloc char[TokenPrefix.Length + versionDigits + 1 + DigestBase32Length];
        TokenPrefix.AsSpan().CopyTo(token);
        int written = TokenPrefix.Length;
        if (!keys.HmacKeyVersion.TryFormat(token[written..], out int formatted))
        {
            throw new InvalidOperationException("failed to format HMAC key version.");
        }

        written += formatted;
        token[written++] = '_';
        written += Base32.EncodeTo(digest, token[written..]);
        return new string(token[..written]);
    }

    public static string Tokenize(ReadOnlySpan<char> value, RedactionKeyring keys)
    {
        int maxByteCount = Encoding.UTF8.GetMaxByteCount(value.Length);
        if (maxByteCount <= StackUtf8Bytes)
        {
            Span<byte> utf8 = stackalloc byte[maxByteCount];
            int length = Encoding.UTF8.GetBytes(value, utf8);
            return Tokenize(utf8[..length], keys);
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(maxByteCount);
        try
        {
            int length = Encoding.UTF8.GetBytes(value, rented);
            return Tokenize(rented.AsSpan(0, length), keys);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    private static int CountDigits(int value)
    {
        int digits = 1;
        while (value >= 10)
        {
            value /= 10;
            digits++;
        }

        return digits;
    }
}
