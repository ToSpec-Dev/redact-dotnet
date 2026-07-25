namespace ToSpec.Redact;

/// <summary>
/// The unwrapped per-tenant redaction HMAC key handed to the redactor for one
/// pass. The version rides inside every emitted token (<c>tsr_v{N}_…</c>) — that
/// is the KEYS.md "capture rows stamp key version" mechanism: after a rotation,
/// old tokens remain queryable by their embedded version; equality across
/// versions is unsupported by design.
/// </summary>
public sealed class RedactionKeyring
{
    private readonly byte[] _hmacKey;

    public RedactionKeyring(byte[] hmacKey, int hmacKeyVersion)
    {
        ArgumentNullException.ThrowIfNull(hmacKey);
        ArgumentOutOfRangeException.ThrowIfLessThan(hmacKeyVersion, 1);
        _hmacKey = hmacKey;
        HmacKeyVersion = hmacKeyVersion;
    }

    public int HmacKeyVersion { get; }

    public ReadOnlySpan<byte> HmacKey => _hmacKey;
}
