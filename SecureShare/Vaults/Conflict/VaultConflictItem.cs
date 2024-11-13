using System.Diagnostics.CodeAnalysis;

namespace VaettirNet.SecureShare.Vaults.Conflict;

public abstract class VaultConflictItem
{
    public abstract bool TryGetAutoResolution([MaybeNullWhen(false)] out VaultResolutionItem resolution);
    public abstract bool TryApplyTo(ref LiveVaultData liveVault, VaultResolutionItem? resolution, VaultCryptographyAlgorithm algorithm);
}
