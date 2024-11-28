using System;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.SecureShare.Crypto;

[PackedBinarySerializable]
public class PrivateKeyInfo
{
    [PackedBinaryMember(1)]
    public Guid Id { get; private set; }
    [PackedBinaryMember(2)]
    public ReadOnlyMemory<byte> EncryptionKey { get; private set; }
    [PackedBinaryMember(3)]
    public ReadOnlyMemory<byte> SigningKey { get; private set; }

    public PrivateKeyInfo(Guid id, ReadOnlyMemory<byte> encryptionKey, ReadOnlyMemory<byte> signingKey)
    {
        EncryptionKey = encryptionKey;
        SigningKey = signingKey;
        Id = id;
    }
}