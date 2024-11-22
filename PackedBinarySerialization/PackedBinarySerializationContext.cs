using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace VaettirNet.PackedBinarySerialization;

public readonly record struct PackedBinarySerializationContext(
    Encoding? Encoding = null,
    long? MaxValue = null,
    bool ImplicitSize = false,
    bool UsePackedIntegers = true,
    TagMap? TagMap = null
)
{
    public PackedBinarySerializationContext Descend() => this with { MaxValue = null, ImplicitSize = false };
}

public class TagMap
{
    private readonly Dictionary<Type, int> _typeToTag = [];
    private readonly Dictionary<int, Type> _tagToType = [];

    public bool TryGetType(int tag, [NotNullWhen(true)] out Type? type)
    {
        return _tagToType.TryGetValue(tag, out type);
    }

    public bool TryGetTag(Type type, out int tag)
    {
        return _typeToTag.TryGetValue(type, out tag);
    }

    public void Add(Type type, int tag)
    {
        _typeToTag.Add(type, tag);
        _tagToType.Add(tag, type);
    }
}