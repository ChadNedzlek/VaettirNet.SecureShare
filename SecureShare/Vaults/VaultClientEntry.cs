using System;
using ProtoBuf;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract(UseProtoMembersOnly = true, SkipConstructor = true)]
public class VaultClientEntry
{
    public PublicClientInfo PublicInfo => new(EncryptionKey, SigningKey);
    [ProtoMember(1)]
    public Guid ClientId { get; private set; }
    [ProtoMember(2)]
    public string Description { get; private set; }
    [ProtoMember(3)]
    public ReadOnlyMemory<byte> EncryptionKey { get; private set; }
    [ProtoMember(4)]
    public ReadOnlyMemory<byte> SigningKey { get; private set; }
    [ProtoMember(5)]
    public ReadOnlyMemory<byte> EncryptedSharedKey { get; private set; }
    [ProtoMember(6)]
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

    public void Deconstruct(
        out Guid clientId,
        out string description,
        out ReadOnlyMemory<byte> encryptionKey,
        out ReadOnlyMemory<byte> signingKey,
        out ReadOnlyMemory<byte> encryptedSharedKey)
    {
        clientId = ClientId;
        description = Description;
        encryptionKey = EncryptionKey;
        signingKey = SigningKey;
        encryptedSharedKey = EncryptedSharedKey;
    }
}