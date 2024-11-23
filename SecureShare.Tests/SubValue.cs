using VaettirNet.PackedBinarySerialization.Attributes;

namespace SecureShare.Tests;

public class SubValue<T> : TestValue
{
    public SubValue(T value)
    {
        Value = value;
    }

    [PackedBinaryMember(2)]
    public T Value { get; private set; }
}