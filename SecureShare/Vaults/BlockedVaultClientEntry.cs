using System;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[PackedBinarySerializable]
public class BlockedVaultClientEntry : IBinarySerializable<BlockedVaultClientEntry>, IComparable<BlockedVaultClientEntry>, IComparable
{
    public static IBinarySerializer<BlockedVaultClientEntry> GetBinarySerializer() => PackedBinaryObjectSerializer<BlockedVaultClientEntry>.Create();
    
    [PackedBinaryMember(1)]
    public Guid ClientId { get; private set; }
    [PackedBinaryMember(2)]
    public string Description { get; private set; }
    [PackedBinaryMember(3)]
    public ReadOnlyMemory<byte> PublicKey { get; private set; }

    public BlockedVaultClientEntry(Guid clientId, string description, ReadOnlyMemory<byte> publicKey)
    {
        ClientId = clientId;
        Description = description;
        PublicKey = publicKey;
    }

    public int CompareTo(BlockedVaultClientEntry other)
    {
        if (ReferenceEquals(this, other)) return 0;
        if (other is null) return 1;
        return ClientId.CompareTo(other.ClientId);
    }

    public int CompareTo(object obj)
    {
        if (obj is null) return 1;
        if (ReferenceEquals(this, obj)) return 0;
        return obj is BlockedVaultClientEntry other ? CompareTo(other) : throw new ArgumentException($"Object must be of type {nameof(BlockedVaultClientEntry)}");
    }
}