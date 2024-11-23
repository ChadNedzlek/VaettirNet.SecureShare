using System;

namespace VaettirNet.PackedBinarySerialization.Attributes;

[AttributeUsage(AttributeTargets.Class)]
public class PackedBinarySerializableAttribute : Attribute
{
    public bool SequentialMembers => MemberLayout == PackedBinaryMemberLayout.Sequential;
    public PackedBinaryMemberLayout MemberLayout {get; set; }
    public bool IncludeNonPublic { get; set; }
}

public enum PackedBinaryMemberLayout
{
    Explicit = 0,
    Sequential,
}