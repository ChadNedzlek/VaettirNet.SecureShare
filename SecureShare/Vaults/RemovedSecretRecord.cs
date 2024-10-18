using System;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract(SkipConstructor = true)]
public class RemovedSecretRecord : BinarySerializable<RemovedSecretRecord>, ISignable<RemovedSecretRecord>
{
    [ProtoMember(1)]
    public Guid Id { get; private set; }
    [ProtoMember(2)]
    public uint Version { get; private set; }
    [ProtoMember(3)]
    public ReadOnlyMemory<byte> Signature { get; private set; }
    [ProtoMember(4)]
    public Guid Authorizer { get; private set; }

    public RemovedSecretRecord(Guid id, uint version, ReadOnlyMemory<byte> signature, Guid authorizer)
    {
        Id = id;
        Version = version;
        Signature = signature;
        Authorizer = authorizer;
    }
}