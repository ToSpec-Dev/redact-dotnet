using System.Buffers;
using System.Text;
using ToSpec.Redact;

namespace ToSpec.Redact.Tests;

/// <summary>
/// The S4.6 streaming XML redactor: the SAME compiled rule trie the JSON pass
/// walks, evaluated over XML structure — name edges match child elements and
/// attributes, [*] matches any child element, descendant scopes stay sticky, the
/// document element (and a SOAP envelope's shell) is the root context. Includes
/// the S1.3 structural guarantee re-run for XML: no PAN survives into the output
/// bytes, wherever it hides.
/// </summary>
public sealed class XmlBodyRedactorTests
{
    private static readonly RedactionKeyring Keys = new(new byte[32], hmacKeyVersion: 1);

    private static CompiledRuleset Compile(string yaml)
    {
        RulesetCompileResult result = RedactionRulesetCompiler.Compile(yaml);
        Assert.True(result.Success, string.Join("; ", result.Errors));
        return result.Ruleset!;
    }

    private static (RedactionResult Result, string Output) Redact(string yaml, string xml)
        => Redact(yaml, Encoding.UTF8.GetBytes(xml));

    private static (RedactionResult Result, string Output) Redact(string yaml, byte[] xml)
    {
        var output = new ArrayBufferWriter<byte>();
        RedactionResult result = XmlBodyRedactor.Instance.Redact(
            new ReadOnlySequence<byte>(xml), output, Compile(yaml), Keys);
        return (result, Encoding.UTF8.GetString(output.WrittenSpan));
    }

    private static string Token(string value) => HmacTokenizer.Tokenize(value.AsSpan(), Keys);

    // ------------------------------------------------------------ path matching

    [Fact]
    public void Redact_ChildPath_MatchesElementUnderTheDocumentRoot()
    {
        // $.payment.cardNumber over XML: the document element IS "$", exactly
        // like the JSON root object — same ruleset, both formats.
        const string yaml = """
            body:
              - { path: "$.payment.cardNumber", action: hash }
            """;
        const string xml =
            "<booking><payment><cardNumber>4111111111111111</cardNumber><amount>12</amount></payment></booking>";

        (RedactionResult first, string output) = Redact(yaml, xml);
        (_, string second) = Redact(yaml, xml);

        Assert.Equal(1, first.ValuesRedacted);
        Assert.Equal(output, second); // deterministic token
        Assert.Contains($"<cardNumber>{Token("4111111111111111")}</cardNumber>", output, StringComparison.Ordinal);
        Assert.Contains("<amount>12</amount>", output, StringComparison.Ordinal);
        Assert.DoesNotContain("4111111111111111", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_NameEdge_AlsoMatchesAnAttribute()
    {
        const string yaml = """
            body:
              - { path: "$.card.number", action: hash }
            """;
        (_, string output) = Redact(yaml, """<r><card number="4111111111111111" brand="visa"/></r>""");

        Assert.DoesNotContain("4111111111111111", output, StringComparison.Ordinal);
        Assert.Contains($"number=\"{Token("4111111111111111")}\"", output, StringComparison.Ordinal);
        Assert.Contains("brand=\"visa\"", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_WildcardIndex_MatchesAnyChildElement()
    {
        // $.items[*].price: JSON's array element = XML's repeated child.
        const string yaml = """
            body:
              - { path: "$.items[*].price", action: drop }
            """;
        (RedactionResult result, string output) = Redact(yaml,
            "<r><items><item><price>1.50</price><sku>a</sku></item>" +
            "<item><price>2.00</price><sku>b</sku></item></items><price>3.00</price></r>");

        Assert.Equal(2, result.ValuesRedacted);
        Assert.DoesNotContain("1.50", output, StringComparison.Ordinal);
        Assert.DoesNotContain("2.00", output, StringComparison.Ordinal);
        Assert.Contains("<price>3.00</price>", output, StringComparison.Ordinal); // top-level unmatched
        Assert.Contains("<sku>a</sku>", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_RecursiveDescent_MatchesElementsAndAttributesAtAllDepths()
    {
        const string yaml = """
            body:
              - { path: "$..password", action: drop }
            """;
        (_, string output) = Redact(yaml,
            """<r><password>a</password><user password="b"><nested><password>c</password><keep>1</keep></nested></user></r>""");

        Assert.DoesNotContain("password", output, StringComparison.Ordinal);
        Assert.Contains("<keep>1</keep>", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_Mask_KeepsShapeNotData()
    {
        const string yaml = """
            body:
              - { path: "$.guest.card", action: mask, keep: last4 }
            """;
        (_, string output) = Redact(yaml, "<r><guest><card>4111111111111111</card></guest></r>");

        Assert.Contains("<card>***1111</card>", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_ScalarActionOnContainer_PlaceholderAndAttributesGone()
    {
        // A hash rule landing on an element with children behaves like the JSON
        // container hit: the whole value (attributes included) is gone.
        const string yaml = """
            body:
              - { path: "$.payment", action: hash }
            """;
        (_, string output) = Redact(yaml,
            """<r><payment currency="USD"><cardNumber>4111111111111111</cardNumber></payment><ok>1</ok></r>""");

        Assert.Contains("<payment>[redacted:container]</payment>", output, StringComparison.Ordinal);
        Assert.DoesNotContain("4111111111111111", output, StringComparison.Ordinal);
        Assert.DoesNotContain("USD", output, StringComparison.Ordinal);
        Assert.Contains("<ok>1</ok>", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_ScalarActionOnSplitText_ReplacesCombinedText()
    {
        const string yaml = """
            body:
              - { path: "$.note", action: mask, keep: last4 }
            """;
        (_, string output) = Redact(yaml, "<r><note>abc<![CDATA[def]]></note></r>");

        Assert.Contains("<note>***cdef</note>", output, StringComparison.Ordinal);
        Assert.DoesNotContain("abcdef", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_SoapEnvelope_RulesAnchorAtTheBodyPayload()
    {
        // The redaction twin of the evaluator's auto-unwrap: $.card hits the
        // payload's child through Envelope/Body, so one ruleset covers wrapped
        // and unwrapped traffic.
        const string yaml = """
            body:
              - { path: "$.card", action: drop }
            """;
        const string xml = """
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
              <soap:Body><BookRQ><card>4111111111111111</card><hotel>H-1</hotel></BookRQ></soap:Body>
            </soap:Envelope>
            """;
        (_, string output) = Redact(yaml, xml);

        Assert.DoesNotContain("4111111111111111", output, StringComparison.Ordinal);
        Assert.Contains("<hotel>H-1</hotel>", output, StringComparison.Ordinal);
        Assert.Contains("Envelope", output, StringComparison.Ordinal); // shell preserved
    }

    [Fact]
    public void Redact_WsseSecurityHeader_AlwaysStripped()
    {
        // SPEC-infrastructure §4: WS-Security strip is a platform default — it is
        // the SOAP spelling of the Authorization header. No rule needs to name it.
        const string yaml = """
            body:
              - { path: "$.unrelated", action: drop }
            """;
        const string xml = """
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                           xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
              <soap:Header><wsse:Security><wsse:UsernameToken>
                <wsse:Username>agent</wsse:Username><wsse:Password>hunter2</wsse:Password>
              </wsse:UsernameToken></wsse:Security></soap:Header>
              <soap:Body><Ping><ok>1</ok></Ping></soap:Body>
            </soap:Envelope>
            """;
        (_, string output) = Redact(yaml, xml);

        Assert.DoesNotContain("hunter2", output, StringComparison.Ordinal);
        Assert.DoesNotContain("UsernameToken", output, StringComparison.Ordinal);
        Assert.Contains("<ok>1</ok>", output, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------ detector layer

    [Fact]
    public void Redact_DeclaredFreetext_HashesDetectorHits()
    {
        const string yaml = """
            body:
              - { path: "$.keep", action: mask }
            freetext:
              fields: ["$.notes"]
              detectors: [pan_luhn, email]
            """;
        (RedactionResult result, string output) = Redact(yaml,
            "<r><notes>guest 4111111111111111 wrote from a@b.com</notes><keep>x</keep></r>");

        Assert.Equal(2, result.DetectorHits);
        Assert.DoesNotContain("4111111111111111", output, StringComparison.Ordinal);
        Assert.DoesNotContain("a@b.com", output, StringComparison.Ordinal);
        Assert.Contains(Token("4111111111111111"), output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_ScanUnknown_SweepsTextAttributesAndCdata()
    {
        const string yaml = """
            body:
              - { path: "$.keep", action: mask }
            freetext:
              scan_unknown: true
              detectors: [pan_luhn]
            defaults:
              unknown_pii_policy: detect_and_drop
            """;
        (_, string output) = Redact(yaml,
            """<r note="pan 4111111111111111 here"><a>4012888888881881</a>""" +
            "<b><![CDATA[card 5555555555554444]]></b><keep>k</keep></r>");

        Assert.DoesNotContain("4111111111111111", output, StringComparison.Ordinal);
        Assert.DoesNotContain("4012888888881881", output, StringComparison.Ordinal);
        Assert.DoesNotContain("5555555555554444", output, StringComparison.Ordinal);
        Assert.Contains("[redacted:pan_luhn]", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_CommentsAndProcessingInstructions_StructurallyDropped()
    {
        const string yaml = """
            body:
              - { path: "$.keep", action: mask }
            """;
        (_, string output) = Redact(yaml,
            "<?xml version=\"1.0\"?><?robots index?><r><!-- pan 4111111111111111 --><keep>k</keep></r>");

        Assert.DoesNotContain("4111111111111111", output, StringComparison.Ordinal);
        Assert.DoesNotContain("robots", output, StringComparison.Ordinal);
        Assert.Contains("<keep>", output, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------ structure preserved

    [Fact]
    public void Redact_UntouchedContent_PreservesNamespacesPrefixesAndCdata()
    {
        const string yaml = """
            body:
              - { path: "$.gone", action: drop }
            """;
        const string xml =
            """<ota:AvailRS xmlns:ota="http://x/ota"><ota:Item RatePlanCode="BAR">ok</ota:Item>""" +
            "<note><![CDATA[a < b]]></note></ota:AvailRS>";
        (_, string output) = Redact(yaml, xml);

        Assert.Contains("<ota:AvailRS", output, StringComparison.Ordinal);
        Assert.Contains("xmlns:ota=\"http://x/ota\"", output, StringComparison.Ordinal);
        Assert.Contains("RatePlanCode=\"BAR\"", output, StringComparison.Ordinal);
        Assert.Contains("<![CDATA[a < b]]>", output, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------ malformed input contract

    [Theory]
    [InlineData("<r><unclosed")]
    [InlineData("not xml at all")]
    [InlineData("<a/><b/>")]
    [InlineData("")]
    [InlineData("   ")]                        // whitespace only — no document element
    [InlineData("\n\t ")]                      // whitespace only (mixed)
    public void Redact_MalformedInput_NeverThrows(string xml)
    {
        const string yaml = """
            body:
              - { path: "$.x", action: drop }
            """;
        (RedactionResult result, _) = Redact(yaml, xml);

        Assert.Equal(RedactionStatus.MalformedInput, result.Status);
    }

    [Fact]
    public void Redact_Iso88591Declaration_DecodesAndRedactsBeforeUtf8Output()
    {
        const string xml =
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r><card>4111111111111111</card><name>José</name></r>";
        (RedactionResult result, string output) = Redact(
            "body:\n  - { path: \"$.card\", action: mask }\n",
            Encoding.Latin1.GetBytes(xml));

        Assert.Equal(RedactionStatus.Rewritten, result.Status);
        Assert.DoesNotContain("4111111111111111", output, StringComparison.Ordinal);
        Assert.Contains("José", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_Utf16LeBom_DecodesAndRedactsBeforeUtf8Output()
    {
        const string xml =
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?><r><card>4111111111111111</card><name>José</name></r>";
        byte[] content = Encoding.Unicode.GetBytes(xml);
        byte[] encoded = [.. Encoding.Unicode.GetPreamble(), .. content];
        (RedactionResult result, string output) = Redact(
            "body:\n  - { path: \"$.card\", action: mask }\n",
            encoded);

        Assert.Equal(RedactionStatus.Rewritten, result.Status);
        Assert.DoesNotContain("4111111111111111", output, StringComparison.Ordinal);
        Assert.Contains("José", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_DoctypeProhibited_MalformedNotResolved()
    {
        // XXE discipline: a DTD in a captured payload is malformed, full stop.
        const string yaml = """
            body:
              - { path: "$.x", action: drop }
            """;
        (RedactionResult result, _) = Redact(yaml,
            "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>");

        Assert.Equal(RedactionStatus.MalformedInput, result.Status);
    }

    [Fact]
    public void Redact_DepthOverSixtyFour_Malformed()
    {
        const string yaml = """
            body:
              - { path: "$.x", action: drop }
            """;
        string xml = string.Concat(Enumerable.Repeat("<a>", 70))
            + string.Concat(Enumerable.Repeat("</a>", 70));
        (RedactionResult result, _) = Redact(yaml, xml);

        Assert.Equal(RedactionStatus.MalformedInput, result.Status);
    }

    // ------------------------------------------------------------ the structural guarantee, XML edition

    [Fact]
    public void Redact_PanScan_NoPanSurvivesAnywhereInTheOutput()
    {
        // S1.3's raw-scan guarantee re-run for XML (S4.6 DoD): with path rules on
        // the declared card fields and the unknown-string sweep on, a PAN must not
        // survive in element text, attributes, CDATA, comments, SOAP headers or
        // free text — scan the OUTPUT BYTES, not the model.
        const string yaml = """
            body:
              - { path: "$..cardNumber", action: hash }
            freetext:
              scan_unknown: true
              detectors: [pan_luhn]
            defaults:
              unknown_pii_policy: detect_and_hash
            """;
        string[] pans =
        [
            "4111111111111111", "4012888888881881", "5555555555554444", "378282246310005",
        ];
        const string xml = """
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                           xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
              <soap:Header><wsse:Security><wsse:Password>4111111111111111</wsse:Password></wsse:Security></soap:Header>
              <soap:Body>
                <BookRQ>
                  <!-- agent noted card 4012888888881881 -->
                  <payment card="5555555555554444"><cardNumber>4111111111111111</cardNumber></payment>
                  <notes><![CDATA[amex 378282246310005 on file]]></notes>
                  <freeText>fallback 4012888888881881 typed by agent</freeText>
                  <hotel>H-1</hotel>
                </BookRQ>
              </soap:Body>
            </soap:Envelope>
            """;

        (RedactionResult result, string output) = Redact(yaml, xml);

        Assert.Equal(RedactionStatus.Rewritten, result.Status);
        foreach (string pan in pans)
        {
            Assert.DoesNotContain(pan, output, StringComparison.Ordinal);
        }

        Assert.Contains("<hotel>H-1</hotel>", output, StringComparison.Ordinal); // clean data intact
    }
}
