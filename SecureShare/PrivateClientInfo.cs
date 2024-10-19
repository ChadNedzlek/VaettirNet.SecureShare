using System;
using ProtoBuf;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract(SkipConstructor = true)]
public class PrivateClientInfo
{
    [ProtoMember(1)]
    public Guid ClientId { get; private set; }
    [ProtoMember(2)]
    public ReadOnlyMemory<byte> EncryptionKey { get; private set; }
    [ProtoMember(3)]
    public ReadOnlyMemory<byte> SigningKey { get; private set; }

    public PrivateClientInfo(Guid clientId, ReadOnlyMemory<byte> encryptionKey, ReadOnlyMemory<byte> signingKey)
    {
        EncryptionKey = encryptionKey;
        SigningKey = signingKey;
        ClientId = clientId;
    }
}