using System;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract(SkipConstructor = true)]
public class ClientModificationRecord : BinarySerializable<ClientModificationRecord>, IBinarySignable<ClientModificationRecord>
{
    [ProtoMember(1)]
    public ClientAction Action { get; private set; }
    [ProtoMember(2)]
    public Guid Client { get; private set; }
    [ProtoMember(3)]
    public ReadOnlyMemory<byte> SigningKey { get; private set; }
    [ProtoMember(4)]
    public ReadOnlyMemory<byte> EncryptionKey { get; private set; }
    [ProtoMember(5)]
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