using System;

namespace VaettirNet.PackedBinarySerialization.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.GenericParameter | AttributeTargets.Field | AttributeTargets.Property, Inherited = false)]
public class PackedBinaryIncludeTypeAttribute : Attribute
{
    public PackedBinaryIncludeTypeAttribute(int tag, Type type)
    {
        Tag = tag;
        Type = type;
    }

    public int Tag { get; }
    public Type Type { get; }
}