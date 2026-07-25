using System.Buffers;
using System.Text;
using System.Xml;

namespace ToSpec.Redact;

/// <summary>
/// The streaming XML redactor (SPEC-cert-gateway-architecture §5.2 "XML via
/// XmlReader equivalent", S4.6): one forward pass, <see cref="XmlReader"/> →
/// <see cref="XmlWriter"/>, no DOM. The SAME compiled trie the JSON pass walks
/// is evaluated NFA-style over the XML structure:
/// <list type="bullet">
/// <item>a name edge matches a child element OR an attribute by local name
/// (namespaces are prefix-noise in hospitality payloads; rules match local names);</item>
/// <item>the <c>[*]</c> edge matches any child element — JSON's "array element"
/// is XML's "repeated child", so <c>$.items[*].card</c> redacts
/// <c>&lt;items&gt;&lt;item&gt;&lt;card&gt;</c>;</item>
/// <item><c>..</c> descendant scopes stay active at every depth, as in JSON.</item>
/// </list>
/// Root anchoring mirrors JSON: the document element IS the root context — its
/// children are the "$" properties, so <c>$.secret</c> redacts
/// <c>&lt;r&gt;&lt;secret&gt;</c> exactly as it redacts <c>{"secret":…}</c>. A SOAP
/// envelope is treated as structure, not data: Envelope/Header/Body and the Body
/// payload element keep the root context, so the same rule paths hit the payload
/// wrapped or unwrapped — the redaction twin of the evaluator's SOAP auto-unwrap.
///
/// A scalar action (hash/tokenize/mask) on a text-only element replaces its text;
/// on an element with children it replaces the whole content with the container
/// placeholder — either way the element's attributes are dropped with the value
/// (the value is gone wholesale, exactly like a JSON container hit). Declared
/// freetext fields and the unknown-string sweep run the same detector layer over
/// element text, CDATA and attribute values. Comments and processing
/// instructions are structurally dropped — a comment can carry a PAN and no rule
/// can address one. WS-Security headers (<c>wsse:Security</c>) are structurally
/// stripped whenever this pass runs (SPEC-infrastructure §4 "WS-Security header
/// strip rules in the default redaction set") — they carry credentials, the SOAP
/// analog of the Authorization header the gateway always strips. DTDs are
/// prohibited (XXE); malformed input returns
/// <see cref="RedactionStatus.MalformedInput"/> — never an exception — and the
/// caller discards the output.
/// </summary>
public sealed class XmlBodyRedactor : IBodyRedactor
{
    public static XmlBodyRedactor Instance { get; } = new();

    private const int MaxDepth = 64;
    private const string ContainerPlaceholder = "[redacted:container]";

    private static readonly string[] WsseNamespaces =
    [
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
        "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd",
    ];

    private static readonly string[] SoapNamespaces =
    [
        "http://schemas.xmlsoap.org/soap/envelope/",
        "http://www.w3.org/2003/05/soap-envelope",
    ];

    private static readonly XmlReaderSettings ReaderSettings = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        CloseInput = true,
        IgnoreComments = false,
        IgnoreProcessingInstructions = false,
    };

    private static readonly XmlWriterSettings WriterSettings = new()
    {
        Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        OmitXmlDeclaration = true, // the input's declaration may lie about the output encoding
        CloseOutput = false,
    };

    public string Format => "xml";

    public RedactionResult Redact(
        in ReadOnlySequence<byte> input,
        IBufferWriter<byte> output,
        CompiledRuleset rules,
        RedactionKeyring keys)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(keys);

        try
        {
            var pass = new Pass(rules, keys);
            try
            {
                using var outputStream = new BufferWriterStream(output);
                using XmlReader reader = XmlReader.Create(OpenInput(input), ReaderSettings);
                using XmlWriter writer = XmlWriter.Create(outputStream, WriterSettings);
                RedactionResult result = pass.Run(reader, writer);
                writer.Flush();
                return result;
            }
            finally
            {
                pass.ReturnBuffers();
            }
        }
        catch (XmlException)
        {
            return new RedactionResult(RedactionStatus.MalformedInput, 0, 0);
        }
        catch (InvalidOperationException)
        {
            // Writer state-machine surface on pathological input — same contract.
            return new RedactionResult(RedactionStatus.MalformedInput, 0, 0);
        }
        catch (ArgumentException)
        {
            // Invalid XML characters/names surfaced by the writer.
            return new RedactionResult(RedactionStatus.MalformedInput, 0, 0);
        }
    }

    private static MemoryStream OpenInput(in ReadOnlySequence<byte> input)
    {
        if (input.IsSingleSegment
            && System.Runtime.InteropServices.MemoryMarshal.TryGetArray(input.First, out ArraySegment<byte> segment))
        {
            return new MemoryStream(segment.Array!, segment.Offset, segment.Count, writable: false);
        }

        return new MemoryStream(input.ToArray(), writable: false);
    }

    /// <summary>Per-call state: the active trie node stack segmented by element frame.</summary>
    private sealed class Pass(CompiledRuleset rules, RedactionKeyring keys)
    {
        private TrieNode[] _states = ArrayPool<TrieNode>.Shared.Rent(64);
        private readonly Frame[] _frames = ArrayPool<Frame>.Shared.Rent(MaxDepth + 2);
        private int _top;
        private int _depth;
        private int _redacted;
        private int _detectorHits;

        public RedactionResult Run(XmlReader reader, XmlWriter writer)
        {
            // Seed: the root set closed over descendants. The virtual document
            // frame's shell marks the document element as structural — it IS the
            // root context, exactly as "$" is the JSON root object.
            AppendWithClosure(rules.BodyRoot, 0);
            int rootCount = _top;
            _frames[_depth++] = new Frame(0, rootCount, OwnedStart: rootCount, InheritFreetext: false, Shell.Document);

            bool advance = true;
            while (!advance || reader.Read())
            {
                advance = true;
                switch (reader.NodeType)
                {
                    case XmlNodeType.Element:
                        advance = HandleElement(reader, writer);
                        break;

                    case XmlNodeType.EndElement:
                    {
                        Frame frame = _frames[--_depth];
                        _top = frame.OwnedStart;
                        writer.WriteFullEndElement();
                        break;
                    }

                    case XmlNodeType.Text:
                        WriteText(writer, reader.Value, asCdata: false);
                        break;

                    case XmlNodeType.CDATA:
                        WriteText(writer, reader.Value, asCdata: true);
                        break;

                    case XmlNodeType.Whitespace:
                    case XmlNodeType.SignificantWhitespace:
                        writer.WriteWhitespace(reader.Value);
                        break;

                    case XmlNodeType.Comment:
                    case XmlNodeType.ProcessingInstruction:
                    case XmlNodeType.XmlDeclaration:
                        break; // structurally dropped — unaddressable carriers (class notes)

                    default:
                        break;
                }
            }

            return new RedactionResult(RedactionStatus.Rewritten, _redacted, _detectorHits);
        }

        public void ReturnBuffers()
        {
            ArrayPool<TrieNode>.Shared.Return(_states, clearArray: true);
            ArrayPool<Frame>.Shared.Return(_frames, clearArray: true);
        }

        /// <summary>Handles one start element. Returns false when the reader is
        /// already positioned on the next node to process (subtree consumed).</summary>
        private bool HandleElement(XmlReader reader, XmlWriter writer)
        {
            if (reader.Depth >= MaxDepth)
            {
                throw new XmlException($"depth exceeds {MaxDepth}.");
            }

            // Structural default: WS-Security blocks carry credentials — always gone.
            if (reader.LocalName == "Security" && IsWsseNamespace(reader.NamespaceURI))
            {
                _redacted++;
                reader.Skip();
                return false;
            }

            Frame parent = _frames[_depth - 1];

            // Structural shells consume no trie edge: the document element, and a
            // SOAP envelope's Envelope/Header/Body plus the Body payload element,
            // all keep the root context (class notes).
            if (ShellFor(parent, reader) is { } shell)
            {
                bool shellEmpty = reader.IsEmptyElement;
                writer.WriteStartElement(reader.Prefix, reader.LocalName, reader.NamespaceURI);
                WriteAttributes(reader, writer, parent.SetStart, parent.SetCount, parent.InheritFreetext);
                if (shellEmpty)
                {
                    writer.WriteEndElement();
                }
                else
                {
                    _frames[_depth++] = new Frame(
                        parent.SetStart, parent.SetCount, _top, parent.InheritFreetext, shell);
                }

                return true;
            }

            int setStart = _top;
            TransitionElement(parent, reader.LocalName);
            (RedactionAction action, MaskShape mask, bool freetext) = Resolve(setStart, _top - setStart);
            freetext |= parent.InheritFreetext;

            switch (action)
            {
                case RedactionAction.Drop:
                    _top = setStart;
                    _redacted++;
                    reader.Skip();
                    return false;

                case RedactionAction.Hash or RedactionAction.TokenizeTyped or RedactionAction.Mask:
                    WriteReplacedElement(reader, writer, action, mask);
                    _top = setStart;
                    return true; // positioned on the (consumed) end element; advance past it

                default:
                    break;
            }

            bool empty = reader.IsEmptyElement;
            writer.WriteStartElement(reader.Prefix, reader.LocalName, reader.NamespaceURI);
            WriteAttributes(reader, writer, setStart, _top - setStart, freetext);

            if (empty)
            {
                _top = setStart;
                writer.WriteEndElement();
            }
            else
            {
                _frames[_depth++] = new Frame(setStart, _top - setStart, setStart, freetext, Shell.None);
            }

            return true;
        }

        /// <summary>Non-null when the element is structure rather than data: the
        /// returned shell is what ITS children see. The document element opens the
        /// root context; a SOAP Envelope keeps its Header/Body structural; the
        /// Body's payload element opens the root context again.</summary>
        private static Shell? ShellFor(Frame parent, XmlReader reader) => parent.Shell switch
        {
            Shell.Document => IsSoap(reader) && reader.LocalName == "Envelope" ? Shell.Envelope : Shell.None,
            Shell.Envelope when IsSoap(reader) && reader.LocalName == "Body" => Shell.Body,
            Shell.Envelope when IsSoap(reader) && reader.LocalName == "Header" => Shell.None,
            Shell.Body => Shell.None, // the payload element = the root object
            _ => null,
        };

        private static bool IsSoap(XmlReader reader) => IsSoapNamespace(reader.NamespaceURI);

        private static bool IsSoapNamespace(string namespaceUri) =>
            namespaceUri == SoapNamespaces[0] || namespaceUri == SoapNamespaces[1];

        private static bool IsWsseNamespace(string namespaceUri) =>
            namespaceUri == WsseNamespaces[0] || namespaceUri == WsseNamespaces[1];

        /// <summary>A scalar action matched the element: its value is replaced
        /// wholesale — text becomes the token/mask, children become the container
        /// placeholder, attributes go with the value. Consumes through the end
        /// element; the caller advances past it.</summary>
        private void WriteReplacedElement(XmlReader reader, XmlWriter writer, RedactionAction action, MaskShape mask)
        {
            writer.WriteStartElement(reader.Prefix, reader.LocalName, reader.NamespaceURI);

            string? text = null;
            StringBuilder? textBuilder = null;
            var container = false;
            if (!reader.IsEmptyElement)
            {
                using XmlReader subtree = reader.ReadSubtree();
                subtree.Read(); // the root of the subtree
                while (subtree.Read())
                {
                    switch (subtree.NodeType)
                    {
                        case XmlNodeType.Element:
                            container = true;
                            break;
                        case XmlNodeType.Text or XmlNodeType.CDATA when subtree.Depth == 1:
                            if (text is null)
                            {
                                text = subtree.Value;
                            }
                            else
                            {
                                textBuilder ??= new StringBuilder(text.Length + subtree.Value.Length).Append(text);
                                textBuilder.Append(subtree.Value);
                            }

                            break;
                        default:
                            break;
                    }
                }
            }

            if (container)
            {
                writer.WriteString(ContainerPlaceholder);
            }
            else
            {
                string? value = textBuilder?.ToString() ?? text;
                if (value is { Length: > 0 })
                {
                    writer.WriteString(action == RedactionAction.Mask
                        ? MaskShapes.Apply(value, mask)
                        : HmacTokenizer.Tokenize(value, keys));
                }
            }

            writer.WriteFullEndElement();
            _redacted++;
        }

        private void WriteAttributes(XmlReader reader, XmlWriter writer, int setStart, int setCount, bool freetext)
        {
            if (!reader.MoveToFirstAttribute())
            {
                return;
            }

            do
            {
                if (reader.NamespaceURI == "http://www.w3.org/2000/xmlns/")
                {
                    writer.WriteAttributeString(reader.Prefix, reader.LocalName, reader.NamespaceURI, reader.Value);
                    continue;
                }

                (RedactionAction action, MaskShape mask, bool attrFreetext) =
                    TransitionLeaf(setStart, setCount, reader.LocalName);
                switch (action)
                {
                    case RedactionAction.Drop:
                        _redacted++;
                        continue;

                    case RedactionAction.Hash or RedactionAction.TokenizeTyped:
                        writer.WriteAttributeString(reader.Prefix, reader.LocalName, reader.NamespaceURI,
                            HmacTokenizer.Tokenize(reader.Value, keys));
                        _redacted++;
                        continue;

                    case RedactionAction.Mask:
                        writer.WriteAttributeString(reader.Prefix, reader.LocalName, reader.NamespaceURI,
                            MaskShapes.Apply(reader.Value, mask));
                        _redacted++;
                        continue;

                    default:
                        writer.WriteAttributeString(reader.Prefix, reader.LocalName, reader.NamespaceURI,
                            ScanValue(reader.Value, freetext || attrFreetext));
                        continue;
                }
            }
            while (reader.MoveToNextAttribute());

            reader.MoveToElement();
        }

        private void WriteText(XmlWriter writer, string value, bool asCdata)
        {
            Frame frame = _frames[_depth - 1];
            string rewritten = ScanValue(value, frame.InheritFreetext);
            if (asCdata && ReferenceEquals(rewritten, value))
            {
                writer.WriteCData(value);
            }
            else
            {
                writer.WriteString(rewritten);
            }
        }

        /// <summary>The detector layer over one text or attribute value, mirroring
        /// the JSON pass: declared freetext scans with hash replacement; otherwise
        /// the unknown-string sweep under the tenant policy.</summary>
        private string ScanValue(string value, bool freetext)
        {
            bool scanAsFreetext = freetext && rules.Freetext.Detectors.Count > 0;
            bool scanUnknown = !scanAsFreetext
                && rules.Freetext.ScanUnknown
                && rules.UnknownPiiPolicy != UnknownPiiPolicy.Off
                && rules.Freetext.Detectors.Count > 0;

            if (!scanAsFreetext && !scanUnknown)
            {
                return value;
            }

            bool hashReplacement = scanAsFreetext || rules.UnknownPiiPolicy == UnknownPiiPolicy.DetectAndHash;
            return Detectors.Scan(value, rules.Freetext.Detectors, hashReplacement, keys, ref _detectorHits) ?? value;
        }

        // ------------------------------------------------------------ trie machinery

        /// <summary>Transition on a child element: name edges, the any-element
        /// wildcard ([*]), and descendant scopes (sticky, as in the JSON pass).</summary>
        private void TransitionElement(Frame parent, string localName)
        {
            int start = _top;
            for (int i = parent.SetStart; i < parent.SetStart + parent.SetCount; i++)
            {
                TrieNode node = _states[i];
                if (node.IsDescendant)
                {
                    AppendWithClosure(node, start);
                }

                if (node.Children.Count > 0 && node.Children.TryGetValue(localName, out TrieNode? child))
                {
                    AppendWithClosure(child, start);
                }

                if (node.AnyIndex is not null)
                {
                    AppendWithClosure(node.AnyIndex, start);
                }
            }
        }

        /// <summary>Resolves an attribute (a leaf: no set is pushed).</summary>
        private (RedactionAction Action, MaskShape Mask, bool Freetext) TransitionLeaf(
            int setStart, int setCount, string localName)
        {
            int start = _top;
            for (int i = setStart; i < setStart + setCount; i++)
            {
                TrieNode node = _states[i];
                if (node.IsDescendant)
                {
                    AppendWithClosure(node, start);
                }

                if (node.Children.Count > 0 && node.Children.TryGetValue(localName, out TrieNode? child))
                {
                    AppendWithClosure(child, start);
                }
            }

            (RedactionAction Action, MaskShape Mask, bool Freetext) resolved =
                Resolve(start, _top - start);
            _top = start;
            return resolved;
        }

        private void AppendWithClosure(TrieNode node, int segmentStart)
        {
            TrieNode? current = node;
            while (current is not null)
            {
                var present = false;
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
            var freetext = false;
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

        private void EnsureStates(int additional)
        {
            if (_top + additional <= _states.Length)
            {
                return;
            }

            int size = _states.Length * 2;
            while (size < _top + additional)
            {
                size *= 2;
            }

            TrieNode[] next = ArrayPool<TrieNode>.Shared.Rent(size);
            Array.Copy(_states, next, _top);
            ArrayPool<TrieNode>.Shared.Return(_states, clearArray: true);
            _states = next;
        }

        /// <summary><see cref="OwnedStart"/> is where this frame's own states begin —
        /// structural shells reference the parent's set without owning it, so the
        /// pop must not truncate the parent's states.</summary>
        private readonly record struct Frame(
            int SetStart, int SetCount, int OwnedStart, bool InheritFreetext, Shell Shell);

        private enum Shell
        {
            None = 0,
            Document = 1,
            Envelope = 2,
            Body = 3,
        }
    }

    /// <summary>Write-only stream over the caller's <see cref="IBufferWriter{T}"/>.</summary>
    private sealed class BufferWriterStream(IBufferWriter<byte> output) : Stream
    {
        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count) =>
            Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Span<byte> destination = output.GetSpan(buffer.Length);
            buffer.CopyTo(destination);
            output.Advance(buffer.Length);
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
