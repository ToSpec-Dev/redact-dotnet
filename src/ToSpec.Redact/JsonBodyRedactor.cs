using System.Buffers;
using System.Text.Json;

namespace ToSpec.Redact;

/// <summary>
/// The streaming JSON redactor (SPEC-cert-gateway-architecture §5.2 "structured
/// pass"): one forward pass, <see cref="Utf8JsonReader"/> → <see cref="Utf8JsonWriter"/>
/// over pooled buffers — no DOM, no <c>JsonDocument</c>. The compiled trie is
/// evaluated NFA-style: an active-state set per depth (recursive-descent nodes are
/// sticky), stored as segments of one pooled node stack so matching allocates
/// nothing per value. <c>drop</c> is decidable from the property name alone, so a
/// dropped property's name is never written and its value is skipped whole.
/// Malformed input (bad JSON, comments, trailing content, depth &gt; 64) returns
/// <see cref="RedactionStatus.MalformedInput"/> — never an exception — and the
/// caller must discard the output buffer.
/// </summary>
public sealed class JsonBodyRedactor : IBodyRedactor
{
    public static JsonBodyRedactor Instance { get; } = new();

    private const int MaxDepth = 64;
    private const string ContainerPlaceholder = "[redacted:container]";

    public string Format => "json";

    public RedactionResult Redact(
        in ReadOnlySequence<byte> input,
        IBufferWriter<byte> output,
        CompiledRuleset rules,
        RedactionKeyring keys)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(keys);

        if (!IsValidUtf8(input))
        {
            return new RedactionResult(RedactionStatus.MalformedInput, 0, 0);
        }

        var pass = new Pass(rules, keys);
        try
        {
            return pass.Run(input, output);
        }
        catch (JsonException)
        {
            return new RedactionResult(RedactionStatus.MalformedInput, 0, 0);
        }
        catch (InvalidOperationException)
        {
            // Utf8JsonReader/Writer misuse surface (e.g. token/state mismatches on
            // pathological input) — same contract as malformed JSON.
            return new RedactionResult(RedactionStatus.MalformedInput, 0, 0);
        }
        finally
        {
            pass.ReturnBuffers();
        }
    }

    private static bool IsValidUtf8(in ReadOnlySequence<byte> input)
    {
        if (input.IsSingleSegment)
        {
            return System.Text.Unicode.Utf8.IsValid(input.FirstSpan);
        }

        int length = checked((int)input.Length);
        byte[] rented = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            input.CopyTo(rented);
            return System.Text.Unicode.Utf8.IsValid(rented.AsSpan(0, length));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    /// <summary>Per-call state: pooled node stack, frame stack, char/byte scratch.</summary>
    private sealed class Pass(CompiledRuleset rules, RedactionKeyring keys)
    {
        private TrieNode[] _states = ArrayPool<TrieNode>.Shared.Rent(64);
        private readonly Frame[] _frames = ArrayPool<Frame>.Shared.Rent(MaxDepth + 1);
        private char[] _chars = ArrayPool<char>.Shared.Rent(1024);
        private byte[] _bytes = ArrayPool<byte>.Shared.Rent(1024);
        private int _top;
        private int _depth;
        private int _redacted;
        private int _detectorHits;

        public RedactionResult Run(in ReadOnlySequence<byte> input, IBufferWriter<byte> output)
        {
            var reader = new Utf8JsonReader(input, new JsonReaderOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = MaxDepth,
            });
            using var writer = new Utf8JsonWriter(output);

            // Seed: the root set is {root} closed over descendants.
            AppendWithClosure(rules.BodyRoot, 0);
            int rootCount = _top;

            ValueContext pending = default;
            bool hasPending = false;

            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                    {
                        ReadOnlySpan<char> name = ReadChars(ref reader);
                        ref Frame frame = ref _frames[_depth - 1];
                        ValueContext context = TransitionName(frame.SetStart, frame.SetCount, name, frame.InheritFreetext);
                        if (context.Action == RedactionAction.Drop)
                        {
                            reader.Skip();
                            _top = context.SetStart;
                            _redacted++;
                            continue;
                        }

                        writer.WritePropertyName(name);
                        pending = context;
                        hasPending = true;
                        break;
                    }

                    case JsonTokenType.StartObject:
                    case JsonTokenType.StartArray:
                    {
                        ValueContext context = ConsumeValueContext(ref pending, ref hasPending, rootCount);
                        if (context.Action == RedactionAction.Drop)
                        {
                            reader.Skip(); // array-element drop: element vanishes, array stays valid
                            _top = context.SetStart;
                            _redacted++;
                            break;
                        }

                        if (context.Action != RedactionAction.None)
                        {
                            // A scalar action (hash/tokenize/mask) matched a container value.
                            writer.WriteStringValue(ContainerPlaceholder);
                            reader.Skip();
                            _top = context.SetStart;
                            _redacted++;
                            break;
                        }

                        PushFrame(in context, isArray: reader.TokenType == JsonTokenType.StartArray);
                        if (reader.TokenType == JsonTokenType.StartArray)
                        {
                            writer.WriteStartArray();
                        }
                        else
                        {
                            writer.WriteStartObject();
                        }

                        break;
                    }

                    case JsonTokenType.EndObject:
                    case JsonTokenType.EndArray:
                    {
                        ref Frame frame = ref _frames[_depth - 1];
                        _top = frame.SetStart;
                        _depth--;
                        if (reader.TokenType == JsonTokenType.EndArray)
                        {
                            writer.WriteEndArray();
                        }
                        else
                        {
                            writer.WriteEndObject();
                        }

                        break;
                    }

                    case JsonTokenType.String:
                    {
                        ValueContext context = ConsumeValueContext(ref pending, ref hasPending, rootCount);
                        WriteString(ref reader, writer, in context);
                        _top = context.SetStart;
                        break;
                    }

                    case JsonTokenType.Number:
                    case JsonTokenType.True:
                    case JsonTokenType.False:
                    {
                        ValueContext context = ConsumeValueContext(ref pending, ref hasPending, rootCount);
                        WriteNonStringScalar(ref reader, writer, in context);
                        _top = context.SetStart;
                        break;
                    }

                    case JsonTokenType.Null:
                    {
                        ValueContext context = ConsumeValueContext(ref pending, ref hasPending, rootCount);
                        if (context.Action != RedactionAction.Drop)
                        {
                            writer.WriteNullValue(); // null carries no information; passes through
                        }
                        else
                        {
                            _redacted++;
                        }

                        _top = context.SetStart;
                        break;
                    }

                    default:
                        throw new JsonException($"unexpected token {reader.TokenType}.");
                }
            }

            writer.Flush();
            return new RedactionResult(RedactionStatus.Rewritten, _redacted, _detectorHits);
        }

        public void ReturnBuffers()
        {
            ArrayPool<TrieNode>.Shared.Return(_states, clearArray: true);
            ArrayPool<Frame>.Shared.Return(_frames, clearArray: true);
            ArrayPool<char>.Shared.Return(_chars, clearArray: true);
            ArrayPool<byte>.Shared.Return(_bytes, clearArray: true);
        }

        /// <summary>The context for the value token now under the reader.</summary>
        private ValueContext ConsumeValueContext(ref ValueContext pending, ref bool hasPending, int rootCount)
        {
            if (hasPending)
            {
                hasPending = false;
                return pending;
            }

            if (_depth > 0)
            {
                ref Frame frame = ref _frames[_depth - 1];
                if (frame.IsArray)
                {
                    // Copy the frame's element template so a pushed child owns a
                    // fresh segment and can never clobber the template on pop.
                    int start = _top;
                    EnsureStates(frame.ElementCount);
                    Array.Copy(_states, frame.ElementStart, _states, start, frame.ElementCount);
                    _top += frame.ElementCount;
                    return new ValueContext(
                        start, frame.ElementCount, frame.ElementAction, frame.ElementMask, frame.ElementFreetext);
                }
            }

            // The root value itself: no rule can target "$", only scan_unknown applies.
            return new ValueContext(0, _depth == 0 ? rootCount : 0, RedactionAction.None, MaskShape.Full, false);
        }

        private void PushFrame(in ValueContext context, bool isArray)
        {
            if (_depth >= MaxDepth)
            {
                throw new JsonException($"depth exceeds {MaxDepth}.");
            }

            ref Frame frame = ref _frames[_depth++];
            frame = new Frame
            {
                SetStart = context.SetStart,
                SetCount = context.SetCount,
                IsArray = isArray,
                InheritFreetext = context.Freetext,
            };

            if (isArray)
            {
                // Element transitions are the same for every element: compute once.
                int start = _top;
                for (int i = frame.SetStart; i < frame.SetStart + frame.SetCount; i++)
                {
                    TrieNode node = _states[i];
                    if (node.IsDescendant)
                    {
                        AppendWithClosure(node, start);
                    }

                    if (node.AnyIndex is not null)
                    {
                        AppendWithClosure(node.AnyIndex, start);
                    }
                }

                frame.ElementStart = start;
                frame.ElementCount = _top - start;
                (frame.ElementAction, frame.ElementMask, bool freetext) = Resolve(start, frame.ElementCount);
                frame.ElementFreetext = freetext || frame.InheritFreetext;
            }
        }

        private ValueContext TransitionName(int sourceStart, int sourceCount, ReadOnlySpan<char> name, bool inheritFreetext)
        {
            int start = _top;
            for (int i = sourceStart; i < sourceStart + sourceCount; i++)
            {
                TrieNode node = _states[i];
                if (node.IsDescendant)
                {
                    AppendWithClosure(node, start);
                }

                if (node.Children.Count > 0)
                {
                    var lookup = node.Children.GetAlternateLookup<ReadOnlySpan<char>>();
                    if (lookup.TryGetValue(name, out TrieNode? child))
                    {
                        AppendWithClosure(child, start);
                    }
                }
            }

            (RedactionAction action, MaskShape mask, bool freetext) = Resolve(start, _top - start);
            return new ValueContext(start, _top - start, action, mask, freetext || inheritFreetext);
        }

        /// <summary>Appends a node (deduped within the segment) plus its recursive-descent closure.</summary>
        private void AppendWithClosure(TrieNode node, int segmentStart)
        {
            TrieNode? current = node;
            while (current is not null)
            {
                bool present = false;
                for (int i = segmentStart; i < _top; i++)
                {
                    if (ReferenceEquals(_states[i], current))
                    {
                        present = true;
                        break;
                    }
                }

                if (!present)
                {
                    EnsureStates(1);
                    _states[_top++] = current;
                }

                current = current.Descendant;
            }
        }

        private (RedactionAction Action, MaskShape Mask, bool Freetext) Resolve(int start, int count)
        {
            RedactionAction action = RedactionAction.None;
            MaskShape mask = MaskShape.Full;
            bool freetext = false;
            for (int i = start; i < start + count; i++)
            {
                TrieNode node = _states[i];
                if (node.Action > action)
                {
                    action = node.Action; // enum order = destructiveness ranking
                    mask = node.Mask;
                }

                freetext |= node.IsFreetext;
            }

            return (action, mask, freetext);
        }

        /// <summary>
        /// Whether the detector sweep runs over this value, and (out) whether matches are
        /// replaced with HMAC tokens (freetext / detect_and_hash) or <c>[redacted:…]</c>
        /// markers (detect_and_drop). Shared by the string and numeric scalar paths so the
        /// §5.2 "final sweep" decision is identical for both token shapes.
        /// </summary>
        private bool ShouldScanFreetext(in ValueContext context, out bool hashReplacement)
        {
            bool scanAsFreetext = context.Freetext && rules.Freetext.Detectors.Count > 0;
            bool scanUnknown = !scanAsFreetext
                && rules.Freetext.ScanUnknown
                && rules.UnknownPiiPolicy != UnknownPiiPolicy.Off
                && rules.Freetext.Detectors.Count > 0;

            hashReplacement = scanAsFreetext || rules.UnknownPiiPolicy == UnknownPiiPolicy.DetectAndHash;
            return scanAsFreetext || scanUnknown;
        }

        private void WriteString(ref Utf8JsonReader reader, Utf8JsonWriter writer, in ValueContext context)
        {
            switch (context.Action)
            {
                case RedactionAction.Hash:
                case RedactionAction.TokenizeTyped:
                {
                    ReadOnlySpan<byte> value = ReadBytes(ref reader);
                    writer.WriteStringValue(HmacTokenizer.Tokenize(value, keys));
                    _redacted++;
                    return;
                }

                case RedactionAction.Mask:
                {
                    writer.WriteStringValue(MaskShapes.Apply(ReadChars(ref reader), context.Mask));
                    _redacted++;
                    return;
                }

                case RedactionAction.Drop: // array-element drop: write nothing
                    _redacted++;
                    return;
            }

            if (ShouldScanFreetext(in context, out bool hashReplacement))
            {
                ReadOnlySpan<char> chars = ReadChars(ref reader);
                string? rewritten = Detectors.Scan(chars, rules.Freetext.Detectors, hashReplacement, keys, ref _detectorHits);
                if (rewritten is not null)
                {
                    writer.WriteStringValue(rewritten);
                }
                else
                {
                    writer.WriteStringValue(chars);
                }

                return;
            }

            // Untouched string. Escape-free contiguous values can be re-emitted from
            // the raw UTF-8 without an unescape/transcode round trip.
            if (!reader.HasValueSequence && reader.ValueSpan.IndexOf((byte)'\\') < 0)
            {
                writer.WriteStringValue(reader.ValueSpan);
            }
            else
            {
                writer.WriteStringValue(ReadChars(ref reader));
            }
        }

        private void WriteNonStringScalar(ref Utf8JsonReader reader, Utf8JsonWriter writer, in ValueContext context)
        {
            switch (context.Action)
            {
                case RedactionAction.Hash:
                case RedactionAction.TokenizeTyped:
                    // Token over the literal JSON text (documented on HmacTokenizer).
                    writer.WriteStringValue(HmacTokenizer.Tokenize(RawLiteral(ref reader), keys));
                    _redacted++;
                    return;

                case RedactionAction.Mask:
                    // Type-shape preserved, value gone.
                    if (reader.TokenType == JsonTokenType.Number)
                    {
                        writer.WriteNumberValue(0);
                    }
                    else
                    {
                        writer.WriteBooleanValue(false);
                    }

                    _redacted++;
                    return;

                case RedactionAction.Drop:
                    _redacted++;
                    return;
            }

            // §5.2 "final sweep of the redacted output": the detector sweep must also see
            // numeric tokens — a Luhn-valid PAN sent as a bare JSON number would otherwise
            // survive scan_unknown / detect_and_hash. Only numbers can carry a detector
            // match (true/false cannot); scan the literal digits. A hit turns the value into
            // a string (token or marker), so the JSON type changes — same as the string path.
            if (reader.TokenType == JsonTokenType.Number
                && ShouldScanFreetext(in context, out bool hashReplacement))
            {
                ReadOnlySpan<char> literal = RawLiteralChars(ref reader);
                string? rewritten = Detectors.Scan(literal, rules.Freetext.Detectors, hashReplacement, keys, ref _detectorHits);
                if (rewritten is not null)
                {
                    writer.WriteStringValue(rewritten);
                    return;
                }
            }

            switch (reader.TokenType)
            {
                case JsonTokenType.Number:
                    writer.WriteRawValue(RawLiteral(ref reader), skipInputValidation: true);
                    break;
                case JsonTokenType.True:
                    writer.WriteBooleanValue(true);
                    break;
                default:
                    writer.WriteBooleanValue(false);
                    break;
            }
        }

        /// <summary>The exact literal bytes of the current non-string token.</summary>
        private ReadOnlySpan<byte> RawLiteral(ref Utf8JsonReader reader)
        {
            if (!reader.HasValueSequence)
            {
                return reader.ValueSpan;
            }

            long length = reader.ValueSequence.Length;
            EnsureBytes(checked((int)length));
            reader.ValueSequence.CopyTo(_bytes);
            return _bytes.AsSpan(0, (int)length);
        }

        /// <summary>
        /// The literal text of the current number token as chars. JSON numbers are ASCII
        /// (digits, sign, '.', 'e'/'E'), so a byte→char widening is exact and allocation-free.
        /// </summary>
        private ReadOnlySpan<char> RawLiteralChars(ref Utf8JsonReader reader)
        {
            ReadOnlySpan<byte> literal = RawLiteral(ref reader);
            EnsureChars(literal.Length);
            for (int i = 0; i < literal.Length; i++)
            {
                _chars[i] = (char)literal[i];
            }

            return _chars.AsSpan(0, literal.Length);
        }

        /// <summary>Unescaped chars of the current string/property-name token.</summary>
        private ReadOnlySpan<char> ReadChars(ref Utf8JsonReader reader)
        {
            long max = reader.HasValueSequence ? reader.ValueSequence.Length : reader.ValueSpan.Length;
            EnsureChars(checked((int)max));
            int written = reader.CopyString(_chars);
            return _chars.AsSpan(0, written);
        }

        /// <summary>Unescaped UTF-8 bytes of the current string token.</summary>
        private ReadOnlySpan<byte> ReadBytes(ref Utf8JsonReader reader)
        {
            long max = reader.HasValueSequence ? reader.ValueSequence.Length : reader.ValueSpan.Length;
            EnsureBytes(checked((int)max));
            int written = reader.CopyString(_bytes);
            return _bytes.AsSpan(0, written);
        }

        private void EnsureStates(int extra)
        {
            if (_top + extra <= _states.Length)
            {
                return;
            }

            TrieNode[] grown = ArrayPool<TrieNode>.Shared.Rent(Math.Max(_states.Length * 2, _top + extra));
            Array.Copy(_states, grown, _top);
            ArrayPool<TrieNode>.Shared.Return(_states, clearArray: true);
            _states = grown;
        }

        private void EnsureChars(int size)
        {
            if (size <= _chars.Length)
            {
                return;
            }

            ArrayPool<char>.Shared.Return(_chars, clearArray: true);
            _chars = ArrayPool<char>.Shared.Rent(size);
        }

        private void EnsureBytes(int size)
        {
            if (size <= _bytes.Length)
            {
                return;
            }

            ArrayPool<byte>.Shared.Return(_bytes, clearArray: true);
            _bytes = ArrayPool<byte>.Shared.Rent(size);
        }

        /// <summary>The trie context a value is evaluated under.</summary>
        private readonly record struct ValueContext(
            int SetStart, int SetCount, RedactionAction Action, MaskShape Mask, bool Freetext);

        private struct Frame
        {
            public int SetStart;
            public int SetCount;
            public bool IsArray;
            public bool InheritFreetext;
            public int ElementStart;
            public int ElementCount;
            public RedactionAction ElementAction;
            public MaskShape ElementMask;
            public bool ElementFreetext;
        }
    }
}
