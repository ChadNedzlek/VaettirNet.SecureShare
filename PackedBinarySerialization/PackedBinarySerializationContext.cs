using System;
using System.Collections.Generic;
using System.Text;

namespace VaettirNet.PackedBinarySerialization;

public readonly record struct PackedBinarySerializationContext(
    Encoding? Encoding = null,
    long? MaxValue = null,
    bool ImplicitSize = false,
    bool UsePackedIntegers = true,
    IReadOnlyDictionary<Type, int>? TypeTags = null
)
{
    public PackedBinarySerializationContext Descend() => this with { MaxValue = null, ImplicitSize = false };
}