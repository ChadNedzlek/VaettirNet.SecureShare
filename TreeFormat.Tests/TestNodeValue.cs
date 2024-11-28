using System;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.TreeFormat.Tests;

[PackedBinarySerializable(MemberLayout = PackedBinaryMemberLayout.Sequential)]
internal class TestNodeValue : NodeValue
{
    public required int Member { get; init; }
    public override bool TryGetDataToSign(Span<byte> destination, out int cb)
    {
        cb = 0;
        return true;
    }
}