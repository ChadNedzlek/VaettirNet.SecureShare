using VaettirNet.PackedBinarySerialization.Attributes;

namespace SecureShare.Tests;

[PackedBinarySerializable]
public class Container
{
    [PackedBinaryMember(1)]
    public TestValue Value { get; private set; }
}