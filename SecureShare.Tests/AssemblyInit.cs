using System;
using FluentAssertions.Formatting;
using NUnit.Framework;

namespace VaettirNet.SecureShare.Tests;

[SetUpFixture]
public static class AssemblyInit
{
    [OneTimeSetUp]
    public static void SetupFormatters()
    {
        Formatter.AddFormatter(new ByteMemoryFormatter());
    }
}

public class ByteMemoryFormatter : IValueFormatter
{
    public bool CanHandle(object value)
    {
        return value switch
        {
            ReadOnlyMemory<byte> => true,
            Memory<byte> => true,
            _ => false,
        };
    }

    public void Format(object value, FormattedObjectGraph formattedGraph, FormattingContext context, FormatChild formatChild)
    {
        ReadOnlyMemory<byte> bytes;
        string prefix = "";
        if (value is Memory<byte> writable)
        {
            bytes = writable;
            prefix = "M:";
        }
        else
        {
            bytes = (ReadOnlyMemory<byte>)value;
            prefix = "ROM:";
        }
        formattedGraph.AddFragment($"{prefix}{Convert.ToBase64String(bytes.Span)}");
    }
}