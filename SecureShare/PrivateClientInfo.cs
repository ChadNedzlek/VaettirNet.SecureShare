using System;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.SecureShare;

[PackedBinarySerializable]
public class PrivateClientInfo
{
    [PackedBinaryMember(1)]
    public Guid ClientId { get; private set; }
    [PackedBinaryMember(2)]
    public ReadOnlyMemory<byte> EncryptionKey { get; private set; }
    [PackedBinaryMember(3)]
    public ReadOnlyMemory<byte> SigningKey { get; private set; }

    public PrivateClientInfo(Guid clientId, ReadOnlyMemory<byte> encryptionKey, ReadOnlyMemory<byte> signingKey)
    {
        EncryptionKey = encryptionKey;
        SigningKey = signingKey;
        ClientId = clientId;
    }
}