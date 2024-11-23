using System;
using System.Text;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[PackedBinarySerializable]
public class VaultRequest : BinarySerializable<VaultRequest>
{
    public VaultRequest(Guid clientId, string description, ReadOnlyMemory<byte> encryptionKey, ReadOnlyMemory<byte> signingKey, ReadOnlyMemory<byte> extraData = default)
    {
        ClientId = clientId;
        Description = description;
        EncryptionKey = encryptionKey;
        SigningKey = signingKey;
        ExtraData = extraData;
    }

    [PackedBinaryMember(1)]
    public Guid ClientId { get; private set; }
    [PackedBinaryMember(2)]
    public string Description { get; }
    [PackedBinaryMember(3)]
    public ReadOnlyMemory<byte> EncryptionKey { get; private set; }
    [PackedBinaryMember(4)]
    public ReadOnlyMemory<byte> SigningKey { get; private set; }
    [PackedBinaryMember(5)]
    public ReadOnlyMemory<byte> ExtraData { get; private set; }
    
    public PublicClientInfo PublicInfo => new PublicClientInfo(ClientId, EncryptionKey, SigningKey);
    
    public static VaultRequest Create(VaultCryptographyAlgorithm algorithm, string description, ReadOnlySpan<char> extraData, out PrivateClientInfo privateInfo)
    {
        byte[] buffer = new byte[Encoding.UTF8.GetMaxByteCount(extraData.Length)];
        int cb = Encoding.UTF8.GetBytes(extraData, buffer);
        return Create(algorithm, description, buffer.AsMemory(0, cb), out privateInfo);
    }
    
    public static VaultRequest Create(VaultCryptographyAlgorithm algorithm, string description, ReadOnlyMemory<byte> extraData, out PrivateClientInfo privateInfo)
    {
        Guid clientId = Guid.NewGuid();
        algorithm.Create(clientId, out privateInfo, out PublicClientInfo publicInfo);
        return Create(description, publicInfo, extraData);
    }

    public static VaultRequest Create(VaultCryptographyAlgorithm algorithm, string description, out PrivateClientInfo privateInfo)
        => Create(algorithm, description, ReadOnlyMemory<byte>.Empty, out privateInfo);

    public static VaultRequest Create(string description, PublicClientInfo publicInfo, ReadOnlySpan<char> extraData)
    {
        byte[] buffer = new byte[Encoding.UTF8.GetMaxByteCount(extraData.Length)];
        int cb = Encoding.UTF8.GetBytes(extraData, buffer);
        return new VaultRequest(publicInfo.ClientId, description, publicInfo.EncryptionKey, publicInfo.SigningKey, buffer.AsMemory(0, cb));
    }

    public static VaultRequest Create(string description, PublicClientInfo publicInfo, ReadOnlyMemory<byte> extraData = default)
    {
        return new VaultRequest(publicInfo.ClientId, description, publicInfo.EncryptionKey, publicInfo.SigningKey, extraData);
    }
}