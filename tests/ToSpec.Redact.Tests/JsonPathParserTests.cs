using ToSpec.Redact;
using Xunit;

namespace ToSpec.Redact.Tests;

public sealed class JsonPathParserTests
{
    [Fact]
    public void TryParse_ChildChain_ParsesInOrder()
    {
        Assert.True(JsonPathParser.TryParse("$.payment.cardNumber", out var segments, out _));
        Assert.Equal(
            [new PathSegment("payment", false), new PathSegment("cardNumber", false)],
            segments);
    }

    [Fact]
    public void TryParse_RecursiveDescent_FlagsSegment()
    {
        Assert.True(JsonPathParser.TryParse("$..password", out var segments, out _));
        Assert.Equal([new PathSegment("password", true)], segments);
    }

    [Fact]
    public void TryParse_WildcardIndex_YieldsNullName()
    {
        Assert.True(JsonPathParser.TryParse("$.comments[*]", out var segments, out _));
        Assert.Equal([new PathSegment("comments", false), new PathSegment(null, false)], segments);
    }

    [Fact]
    public void TryParse_QuotedName_AllowsSpecialCharacters()
    {
        Assert.True(JsonPathParser.TryParse("$['guest name'].email", out var segments, out _));
        Assert.Equal([new PathSegment("guest name", false), new PathSegment("email", false)], segments);
    }

    [Fact]
    public void TryParse_DescendantWildcard_ParsesBoth()
    {
        Assert.True(JsonPathParser.TryParse("$..cards[*].pan", out var segments, out _));
        Assert.Equal(
            [new PathSegment("cards", true), new PathSegment(null, false), new PathSegment("pan", false)],
            segments);
    }

    [Theory]
    [InlineData("$.items[?(@.price)]", "filter expressions")]
    [InlineData("$.items[3]", "numeric array indexes")]
    [InlineData("payment.cardNumber", "must start with '$'")]
    [InlineData("$", "must name a location")]
    [InlineData("$.a b", "quote names")]
    [InlineData("$.", "trailing '.'")]
    [InlineData("$.items[*", "'[*' must close as '[*]'")]
    public void TryParse_ExcludedConstructs_FailWithSpecificMessage(string path, string expectedFragment)
    {
        Assert.False(JsonPathParser.TryParse(path, out _, out string? error));
        Assert.Contains(expectedFragment, error, StringComparison.Ordinal);
    }
}
