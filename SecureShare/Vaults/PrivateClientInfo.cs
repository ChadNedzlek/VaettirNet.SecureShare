using System;

namespace VaettirNet.SecureShare.Vaults;

public struct PrivateClientInfo
{
    public readonly Guid ClientId;
    public readonly ReadOnlyMemory<byte> EncryptionKey;
    public readonly ReadOnlyMemory<byte> SigningKey;

    public PrivateClientInfo(Guid clientId, ReadOnlyMemory<byte> encryptionKey, ReadOnlyMemory<byte> signingKey)
    {
        EncryptionKey = encryptionKey;
        SigningKey = signingKey;
        ClientId = clientId;
    }
}