using System;
using ProtoBuf;

namespace VaettirNet.SecureShare.Secrets;

[ProtoContract]
public class UntypedSealedValue
{
    [ProtoMember(1)]
    public required Guid Id { get; init; }

    [ProtoMember(5)]
    public int Version { get; init; }

    [ProtoMember(6)]
    public required ReadOnlyMemory<byte> HashBytes { get; init; }
}