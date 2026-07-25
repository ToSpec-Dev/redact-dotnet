namespace ToSpec.Redact;

// YAML-facing DTOs for the §5.1 rule model. Deserialization targets only — dumb,
// nullable, mutable; the compiler validates and never lets them past compile.
// Key names bind via UnderscoredNamingConvention (scan_unknown → ScanUnknown).

internal sealed class RedactionDocumentYaml
{
    public RedactionRulesYaml? Redaction { get; set; }
}

internal sealed class RedactionRulesYaml
{
    public HeaderRulesYaml? Headers { get; set; }

    public List<BodyRuleYaml>? Body { get; set; }

    public FreetextYaml? Freetext { get; set; }

    public DefaultsYaml? Defaults { get; set; }
}

internal sealed class HeaderRulesYaml
{
    public List<string>? Strip { get; set; }

    public List<string>? Hash { get; set; }
}

internal sealed class BodyRuleYaml
{
    public string? Path { get; set; }

    public string? Action { get; set; }

    public string? Keep { get; set; }

    public bool? Assertable { get; set; }
}

internal sealed class FreetextYaml
{
    public List<string>? Fields { get; set; }

    public bool? ScanUnknown { get; set; }

    public List<string>? Detectors { get; set; }
}

internal sealed class DefaultsYaml
{
    public string? UnknownPiiPolicy { get; set; }
}
