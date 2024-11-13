using System;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract(SkipConstructor = true)]
public class BlockedVaultClientEntry : IBinarySerializable<BlockedVaultClientEntry>, IComparable<BlockedVaultClientEntry>, IComparable
{
    public static IBinarySerializer<BlockedVaultClientEntry> GetBinarySerializer() => ProtobufObjectSerializer<BlockedVaultClientEntry>.Create();
    
    [ProtoMember(1)]
    public Guid ClientId { get; private set; }
    [ProtoMember(2)]
    public string Description { get; private set; }
    [ProtoMember(3)]
    public ReadOnlyMemory<byte> PublicKey { get; private set; }

    public BlockedVaultClientEntry(Guid clientId, string description, ReadOnlyMemory<byte> publicKey)
    {
        ClientId = clientId;
        Description = description;
        PublicKey = publicKey;
    }

    public int CompareTo(BlockedVaultClientEntry? other)
    {
        if (ReferenceEquals(this, other)) return 0;
        if (other is null) return 1;
        return ClientId.CompareTo(other.ClientId);
    }

    public int CompareTo(object? obj)
    {
        if (obj is null) return 1;
        if (ReferenceEquals(this, obj)) return 0;
        return obj is BlockedVaultClientEntry other ? CompareTo(other) : throw new ArgumentException($"Object must be of type {nameof(BlockedVaultClientEntry)}");
    }
}