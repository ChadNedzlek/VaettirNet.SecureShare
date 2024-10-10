using System;

namespace SecureShare;

public class SealedVault
{
    public SealedVault(VaultData data, Guid clientId)
    {
        Data = data;
        ClientId = clientId;
    }

    public VaultData Data { get; }
    public Guid ClientId { get; }
}