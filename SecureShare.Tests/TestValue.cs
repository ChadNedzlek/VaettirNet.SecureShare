using VaettirNet.PackedBinarySerialization.Attributes;

namespace SecureShare.Tests;

public class TestValue
{
    [PackedBinaryMember(1)]
    public Guid Id { get; private set; }
}