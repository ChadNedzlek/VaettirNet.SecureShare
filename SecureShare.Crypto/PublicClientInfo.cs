using System;

namespace VaettirNet.SecureShare.Crypto;

public struct PublicKeyInfo
{
    public readonly Guid Id;
    public readonly ReadOnlyMemory<byte> EncryptionKey;
    public readonly ReadOnlyMemory<byte> SigningKey;

    public PublicKeyInfo(Guid id, ReadOnlyMemory<byte> encryptionKey, ReadOnlyMemory<byte> signingKey)
    {
        EncryptionKey = encryptionKey;
        SigningKey = signingKey;
        Id = id;
    }
}