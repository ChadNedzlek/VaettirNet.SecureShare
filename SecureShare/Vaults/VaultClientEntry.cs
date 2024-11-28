using System;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.SecureShare.Vaults;

[PackedBinarySerializable]
public class VaultClientEntry : IComparable<VaultClientEntry>, IComparable, IEquatable<VaultClientEntry>
{
    public PublicKeyInfo PublicInfo => new(ClientId, EncryptionKey, SigningKey);
    [PackedBinaryMember(1)]
    public Guid ClientId { get; private set; }
    [PackedBinaryMember(2)]
    public string Description { get; private set; }
    [PackedBinaryMember(3)]
    public ReadOnlyMemory<byte> EncryptionKey { get; private set; }
    [PackedBinaryMember(4)]
    public ReadOnlyMemory<byte> SigningKey { get; private set; }
    [PackedBinaryMember(5)]
    public ReadOnlyMemory<byte> EncryptedSharedKey { get; private set; }
    [PackedBinaryMember(6)]
    public Guid Authorizer { get; private set; }

    public VaultClientEntry(Guid clientId, string description, ReadOnlyMemory<byte> encryptionKey, ReadOnlyMemory<byte> signingKey, ReadOnlyMemory<byte> encryptedSharedKey, Guid authorizer)
    {
        ClientId = clientId;
        Description = description;
        EncryptionKey = encryptionKey;
        SigningKey = signingKey;
        EncryptedSharedKey = encryptedSharedKey;
        Authorizer = authorizer;
    }
    
    public int CompareTo(VaultClientEntry other)
    {
        if (ReferenceEquals(this, other)) return 0;
        if (other is null) return 1;
        return ClientId.CompareTo(other.ClientId);
    }

    public int CompareTo(object obj)
    {
        if (obj is null) return 1;
        if (ReferenceEquals(this, obj)) return 0;
        return obj is VaultClientEntry other ? CompareTo(other) : throw new ArgumentException($"Object must be of type {nameof(VaultClientEntry)}");
    }

    public bool Equals(VaultClientEntry other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        return ClientId.Equals(other.ClientId) && Description == other.Description;
    }

    public override bool Equals(object obj)
    {
        if (obj is null) return false;
        if (ReferenceEquals(this, obj)) return true;
        if (obj.GetType() != GetType()) return false;
        return Equals((VaultClientEntry)obj);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(ClientId, Description);
    }
}