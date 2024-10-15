using System;
using System.Collections.Immutable;

namespace VaettirNet.SecureShare.Vaults;

public class VaultRequest
{
    public VaultRequest(Guid clientId, string description, ReadOnlyMemory<byte> encryptionKey, ReadOnlyMemory<byte> signingKey)
    {
        ClientId = clientId;
        Description = description;
        EncryptionKey = encryptionKey;
        SigningKey = signingKey;
    }

    public Guid ClientId { get; }
    public string Description { get; }
    public ReadOnlyMemory<byte> EncryptionKey { get; }
    public ReadOnlyMemory<byte> SigningKey { get; }
}