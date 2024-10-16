using System;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract]
public class ClientModificationRecord : BinarySerializable<ClientModificationRecord>, ISignable<ClientModificationRecord>
{
    [ProtoMember(1)]
    public required ClientAction Action { get; init; }
    [ProtoMember(2)]
    public required Guid Client { get; init; }
    [ProtoMember(3)]
    public required ReadOnlyMemory<byte> SigningKey { get; init; }
    [ProtoMember(4)]
    public required ReadOnlyMemory<byte> EncryptionKey { get; init; }
    [ProtoMember(5)]
    public required Guid Authorizer { get; init; }
}