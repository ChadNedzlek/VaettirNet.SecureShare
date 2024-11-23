using System;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[PackedBinarySerializable]
public class ClientModificationRecord : BinarySerializable<ClientModificationRecord>, IBinarySignable<ClientModificationRecord>
{
    [PackedBinaryMember(1)]
    public ClientAction Action { get; private set; }
    [PackedBinaryMember(2)]
    public Guid Client { get; private set; }
    [PackedBinaryMember(3)]
    public ReadOnlyMemory<byte> SigningKey { get; private set; }
    [PackedBinaryMember(4)]
    public ReadOnlyMemory<byte> EncryptionKey { get; private set; }
    [PackedBinaryMember(5)]
    public Guid Signer { get; private set; }

    public ClientModificationRecord(ClientAction action, Guid client, ReadOnlyMemory<byte> signingKey, ReadOnlyMemory<byte> encryptionKey, Guid authorizer)
    {
        Action = action;
        Client = client;
        SigningKey = signingKey;
        EncryptionKey = encryptionKey;
        Signer = authorizer;
    }
}