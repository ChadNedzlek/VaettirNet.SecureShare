using System;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract(SkipConstructor = true)]
public class RemovedSecretRecord : BinarySerializable<RemovedSecretRecord>, IBinarySignable<RemovedSecretRecord>
{
    [ProtoMember(1)]
    public Guid Id { get; private set; }
    [ProtoMember(2)]
    public uint Version { get; private set; }
    [ProtoMember(3)]
    public ReadOnlyMemory<byte> Signature { get; private set; }

    public RemovedSecretRecord(Guid id, uint version, ReadOnlyMemory<byte> signature)
    {
        Id = id;
        Version = version;
        Signature = signature;
    }
}