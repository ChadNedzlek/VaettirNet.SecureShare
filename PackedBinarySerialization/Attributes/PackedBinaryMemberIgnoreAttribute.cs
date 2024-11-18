using System;

namespace VaettirNet.PackedBinarySerialization.Attributes;

[AttributeUsage(AttributeTargets.Field | AttributeTargets.Property)]
public class PackedBinaryMemberIgnoreAttribute : Attribute
{
}