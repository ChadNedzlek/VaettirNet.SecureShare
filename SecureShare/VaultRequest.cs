using System;
using System.Collections.Immutable;

namespace SecureShare;

public class VaultRequest
{
    public VaultRequest(Guid clientId, string description, ImmutableArray<byte> publicKey)
    {
        ClientId = clientId;
        Description = description;
        PublicKey = publicKey;
    }

    public Guid ClientId { get; }
    public string Description { get; }
    public ImmutableArray<byte> PublicKey { get; }
}