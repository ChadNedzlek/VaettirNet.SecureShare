using ProtoBuf;

namespace TreeFormat.Tests;

[ProtoContract]
internal class TestNodeValue : NodeValue
{
    [ProtoMember(1)]
    public required int Member { get; init; }
}