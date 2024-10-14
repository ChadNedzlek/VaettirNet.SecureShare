using System;
using System.Collections.Immutable;

namespace VaettirNet.SecureShare.Vaults;

public class VaultRequest
{
    public VaultRequest(Guid clientId, string description, ReadOnlyMemory<byte> publicKey)
    {
        ClientId = clientId;
        Description = description;
        PublicKey = publicKey;
    }

    public Guid ClientId { get; }
    public string Description { get; }
    public ReadOnlyMemory<byte> PublicKey { get; }
}