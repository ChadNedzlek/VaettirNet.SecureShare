using System;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract]
public class BlockedVaultClientEntry : IBinarySerializable<BlockedVaultClientEntry>
{
    public static IBinarySerializer<BlockedVaultClientEntry> GetBinarySerializer() => ProtobufObjectSerializer<BlockedVaultClientEntry>.Create();
    
    [ProtoMember(1)]
    public required Guid ClientId { get; init; }
    [ProtoMember(2)]
    public required string Description { get; init; }
    [ProtoMember(3)]
    public required ReadOnlyMemory<byte> PublicKey { get; init; }

    public void Deconstruct(out Guid clientId, out string description, out ReadOnlyMemory<byte> publicKey)
    {
        clientId = ClientId;
        description = Description;
        publicKey = PublicKey;
    }
}