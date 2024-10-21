using System;
using System.Text;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract(SkipConstructor = true)]
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

    [ProtoMember(1)]
    public Guid ClientId { get; private set; }
    [ProtoMember(2)]
    public string Description { get; }
    [ProtoMember(3)]
    public ReadOnlyMemory<byte> EncryptionKey { get; private set; }
    [ProtoMember(4)]
    public ReadOnlyMemory<byte> SigningKey { get; private set; }
    [ProtoMember(5)]
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
        algorithm.Create(clientId, out privateInfo, out var publicInfo);
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