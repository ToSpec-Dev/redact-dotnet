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

    /// <summary>Upper bound of any token's length in chars: the prefix, at most
    /// 10 version digits, <c>_</c>, and 52 base32 chars. Size
    /// <see cref="TokenizeTo"/> destinations with this.</summary>
    public const int MaxTokenLength = 5 + 10 + 1 + DigestBase32Length;

    // One keyed HMAC state per thread, reset between values instead of re-deriving
    // the key schedule (two SHA-256 block passes) on every token. Keyed on key
    // CONTENT, not keyring identity — consumers may build a fresh keyring per
    // pass — and the 32-byte compare per token is noise next to the digest.
    // Thread-affine, so no locking; the instance lives for the thread's lifetime.
    [ThreadStatic]
    private static byte[]? _cachedKey;

    [ThreadStatic]
    private static IncrementalHash? _cachedHmac;

    public static string Tokenize(ReadOnlySpan<byte> valueUtf8, RedactionKeyring keys)
    {
        Span<char> token = stackalloc char[MaxTokenLength];
        return new string(token[..TokenizeTo(valueUtf8, keys, token)]);
    }

    /// <summary>Writes the token for <paramref name="valueUtf8"/> into
    /// <paramref name="destination"/> (sized by <see cref="MaxTokenLength"/>) and
    /// returns the chars written — the allocation-free form the streaming
    /// redactors emit through directly. A body hashing every element of a grown
    /// array previously allocated one fresh token string per element (the README's
    /// known Typical-shape cost; platform perf review P2).</summary>
    public static int TokenizeTo(ReadOnlySpan<byte> valueUtf8, RedactionKeyring keys, Span<char> destination)
    {
        ArgumentNullException.ThrowIfNull(keys);

        Span<byte> digest = stackalloc byte[HMACSHA256.HashSizeInBytes];
        IncrementalHash hmac = KeyedHmac(keys);
        hmac.AppendData(valueUtf8);
        if (!hmac.TryGetHashAndReset(digest, out _))
        {
            throw new InvalidOperationException("failed to compute the token digest.");
        }

        TokenPrefix.AsSpan().CopyTo(destination);
        int written = TokenPrefix.Length;
        if (!keys.HmacKeyVersion.TryFormat(destination[written..], out int formatted))
        {
            throw new InvalidOperationException("failed to format HMAC key version.");
        }

        written += formatted;
        destination[written++] = '_';
        written += Base32.EncodeTo(digest, destination[written..]);
        return written;
    }

    private static IncrementalHash KeyedHmac(RedactionKeyring keys)
    {
        if (_cachedKey is null || !keys.HmacKey.SequenceEqual(_cachedKey))
        {
            _cachedHmac?.Dispose();
            _cachedHmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, keys.HmacKey);
            _cachedKey = keys.HmacKey.ToArray();
        }

        return _cachedHmac!;
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

}
