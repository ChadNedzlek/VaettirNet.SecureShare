using System.Collections.Immutable;

namespace VaettirNet.SecureShare.Vaults.Conflict;

public class VaultConflictResult
{
    public ValidatedVaultDataSnapshot BaseUnvalidatedVault { get; }
    public ImmutableList<VaultConflictItem> Items { get; }
    
    public VaultConflictResult(ValidatedVaultDataSnapshot baseUnvalidatedVault, ImmutableList<VaultConflictItem> items)
    {
        BaseUnvalidatedVault = baseUnvalidatedVault;
        Items = items;
    }
}