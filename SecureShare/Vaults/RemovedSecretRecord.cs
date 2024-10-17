using System;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract]
public class RemovedSecretRecord : BinarySerializable<RemovedSecretRecord>, ISignable<RemovedSecretRecord>
{
    [ProtoMember(1)]
    public required Guid Id { get; init; }
    [ProtoMember(2)]
    public required uint Version { get; init; }
    [ProtoMember(3)]
    public required ReadOnlyMemory<byte> Signature { get; init; }
    [ProtoMember(4)]
    public required Guid Authorizer { get; init; }
}