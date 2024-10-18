using System;

namespace VaettirNet.SecureShare.Vaults;

public class SealedVault
{
    public SealedVault(LiveVaultData data, Guid clientId)
    {
        Data = data;
        ClientId = clientId;
    }

    public LiveVaultData Data { get; }
    public Guid ClientId { get; }
}