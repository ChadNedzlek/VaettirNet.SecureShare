using ProtoBuf;

namespace SecureShare.Tests;

public class Container
{
    [ProtoMember(1)]
    public TestValue Value { get; private set; }
}