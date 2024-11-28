using System;
using System.Text;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Crypto;
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
    
    public PublicKeyInfo PublicInfo => new PublicKeyInfo(ClientId, EncryptionKey, SigningKey);
    
    public static VaultRequest Create(VaultCryptographyAlgorithm algorithm, string description, ReadOnlySpan<char> extraData, out PrivateKeyInfo privateInfo)
    {
        byte[] buffer = new byte[Encoding.UTF8.GetMaxByteCount(extraData.Length)];
        int cb = Encoding.UTF8.GetBytes(extraData, buffer);
        return Create(algorithm, description, buffer.AsMemory(0, cb), out privateInfo);
    }
    
    public static VaultRequest Create(VaultCryptographyAlgorithm algorithm, string description, ReadOnlyMemory<byte> extraData, out PrivateKeyInfo privateInfo)
    {
        Guid clientId = Guid.NewGuid();
        algorithm.CreateKeys(clientId, out privateInfo, out PublicKeyInfo publicInfo);
        return Create(description, publicInfo, extraData);
    }

    public static VaultRequest Create(VaultCryptographyAlgorithm algorithm, string description, out PrivateKeyInfo privateInfo)
        => Create(algorithm, description, ReadOnlyMemory<byte>.Empty, out privateInfo);

    public static VaultRequest Create(string description, PublicKeyInfo publicInfo, ReadOnlySpan<char> extraData)
    {
        byte[] buffer = new byte[Encoding.UTF8.GetMaxByteCount(extraData.Length)];
        int cb = Encoding.UTF8.GetBytes(extraData, buffer);
        return new VaultRequest(publicInfo.Id, description, publicInfo.EncryptionKey, publicInfo.SigningKey, buffer.AsMemory(0, cb));
    }

    public static VaultRequest Create(string description, PublicKeyInfo publicInfo, ReadOnlyMemory<byte> extraData = default)
    {
        return new VaultRequest(publicInfo.Id, description, publicInfo.EncryptionKey, publicInfo.SigningKey, extraData);
    }
}