using System;

namespace VaettirNet.SecureShare.Vaults;

public struct PublicClientInfo
{
    public readonly Guid ClientId;
    public readonly ReadOnlyMemory<byte> EncryptionKey;
    public readonly ReadOnlyMemory<byte> SigningKey;

    public PublicClientInfo(Guid clientId, ReadOnlyMemory<byte> encryptionKey, ReadOnlyMemory<byte> signingKey)
    {
        EncryptionKey = encryptionKey;
        SigningKey = signingKey;
        ClientId = clientId;
    }
}