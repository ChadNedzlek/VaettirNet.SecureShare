using System;
using ProtoBuf;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract(UseProtoMembersOnly = true, SkipConstructor = true)]
public class VaultClientEntry
{
    public PublicClientInfo PublicInfo => new(EncryptionKey, SigningKey);
    [ProtoMember(1)]
    public required Guid ClientId { get; init; }
    [ProtoMember(2)]
    public required string Description { get; init; }
    [ProtoMember(3)]
    public required ReadOnlyMemory<byte> EncryptionKey { get; init; }
    [ProtoMember(4)]
    public required ReadOnlyMemory<byte> SigningKey { get; init; }
    [ProtoMember(5)]
    public ReadOnlyMemory<byte> EncryptedSharedKey { get; init; }

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