using ProtoBuf;

namespace SecureShare.Tests;

public class TestValue
{
    [ProtoMember(1)]
    public Guid Id { get; private set; }
}