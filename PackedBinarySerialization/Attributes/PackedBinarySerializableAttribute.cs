using System;

namespace VaettirNet.PackedBinarySerialization.Attributes;

[AttributeUsage(AttributeTargets.Class)]
public class PackedBinarySerializableAttribute : Attribute
{
    public bool SequentialMembers { get; set; }
    public bool IncludeNonPublic { get; set; }
}