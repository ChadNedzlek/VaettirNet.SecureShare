using VaettirNet.PackedBinarySerialization.Attributes;

namespace TreeFormat.Tests;

[PackedBinarySerializable(MemberLayout = PackedBinaryMemberLayout.Sequential)]
internal class TestNodeValue : NodeValue
{
    public required int Member { get; init; }
}