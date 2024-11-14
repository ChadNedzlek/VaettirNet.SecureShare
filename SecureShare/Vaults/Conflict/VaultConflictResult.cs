using System.Collections.Immutable;

namespace VaettirNet.SecureShare.Vaults.Conflict;

public class VaultConflictResult
{
    public ValidatedVaultDataSnapshot BaseVault { get; }
    public ImmutableList<VaultConflictItem> Items { get; }
    
    public VaultConflictResult(ValidatedVaultDataSnapshot baseVault, ImmutableList<VaultConflictItem> items)
    {
        BaseVault = baseVault;
        Items = items;
    }

    public PartialVaultConflictResolution GetResolver() => new(BaseVault, Items);
}