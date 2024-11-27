using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.TreeFormat.Tests;

[PackedBinarySerializable(MemberLayout = PackedBinaryMemberLayout.Sequential)]
internal class TestNodeValue : NodeValue
{
    public required int Member { get; init; }
}