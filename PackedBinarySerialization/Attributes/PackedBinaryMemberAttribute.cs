using System;

namespace VaettirNet.PackedBinarySerialization.Attributes;

[AttributeUsage(AttributeTargets.Field | AttributeTargets.Property)]
public class PackedBinaryMemberAttribute : Attribute
{
    public PackedBinaryMemberAttribute(int order)
    {
        Order = order;
    }

    public int Order { get; }
}