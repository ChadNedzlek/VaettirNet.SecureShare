using ProtoBuf;

namespace SecureShare.Tests;

public class SubValue<T> : TestValue
{
    public SubValue(T value)
    {
        Value = value;
    }

    [ProtoMember(2)]
    public T Value { get; private set; }
}