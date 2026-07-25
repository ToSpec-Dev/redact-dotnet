namespace ToSpec.Redact;

/// <summary>
/// RFC 4648 base32 encoder — lowercase, no padding — for redaction HMAC tokens
/// (SPEC-cert-gateway-architecture §5.2 "base32 token"). Encode-only: tokens are
/// opaque replacement values; nothing ever decodes one.
/// </summary>
public static class Base32
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return string.Empty;
        }

        // 5 bytes -> 8 chars; partial final group emitted without padding.
        var result = new char[(data.Length * 8 + 4) / 5];
        int written = EncodeTo(data, result);
        return new string(result, 0, written);
    }

    internal static int EncodeTo(ReadOnlySpan<byte> data, Span<char> destination)
    {
        if (data.IsEmpty)
        {
            return 0;
        }

        int required = (data.Length * 8 + 4) / 5;
        if (destination.Length < required)
        {
            throw new ArgumentException("Destination is too small.", nameof(destination));
        }

        int bitBuffer = 0;
        int bitCount = 0;
        int written = 0;

        foreach (byte b in data)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitCount += 8;
            while (bitCount >= 5)
            {
                bitCount -= 5;
                destination[written++] = Alphabet[(bitBuffer >> bitCount) & 0x1F];
            }
        }

        if (bitCount > 0)
        {
            destination[written++] = Alphabet[(bitBuffer << (5 - bitCount)) & 0x1F];
        }

        return written;
    }
}
