using System;
using ProtoBuf;

namespace VaettirNet.SecureShare.Secrets;

[ProtoContract(SkipConstructor = true)]
public class UntypedSealedSecret
{
    [ProtoMember(1)]
    public Guid Id { get; private set; }

    [ProtoMember(5)]
    public uint Version { get; private set; }

    [ProtoMember(6)]
    public ReadOnlyMemory<byte> HashBytes { get; private set; }

    public UntypedSealedSecret(Guid id, uint version, ReadOnlyMemory<byte> hashBytes)
    {
        Id = id;
        Version = version;
        HashBytes = hashBytes;
    }
}