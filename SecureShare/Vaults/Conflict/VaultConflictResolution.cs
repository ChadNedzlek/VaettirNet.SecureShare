using System;
using System.Collections.Immutable;
using System.Linq;

namespace VaettirNet.SecureShare.Vaults.Conflict;

public class VaultConflictResolution
{
    private VaultConflictResolution(ValidatedVaultDataSnapshot baseVault, ImmutableList<VaultConflictItem> items)
    {
        BaseVault = baseVault;
        Items = items;
    }

    public ValidatedVaultDataSnapshot BaseVault { get; }
    public ImmutableList<VaultConflictItem> Items { get; }

    public class Builder
    {
        private readonly ValidatedVaultDataSnapshot _baseVault;
        private readonly ImmutableList<VaultConflictItem> _items;
        private readonly VaultResolutionItem?[] _resolutions;

        public Builder(ValidatedVaultDataSnapshot baseVault, ImmutableList<VaultConflictItem> items)
        {
            _baseVault = baseVault;
            _items = items;
            _resolutions = new VaultResolutionItem[items.Count];
        }

        public Builder Resolve(VaultConflictItem conflict, VaultResolutionItem resolution)
        {
            _resolutions[_items.IndexOf(conflict)] = resolution;
            return this;
        }

        public OneOf<ValidatedVaultDataSnapshot, VaultResolutionItem> Apply(VaultCryptographyAlgorithm algorithm, PrivateClientInfo signer, VaultResolutionItem? defaultResolution = null)
        {
            if (_resolutions.Any(r => r is null) && defaultResolution is null)
            {
                throw new InvalidOperationException("Not all conflicts are resolved");
            }

            LiveVaultData liveVault = LiveVaultData.FromSnapshot(_baseVault);

            for (int i = 0; i < _resolutions.Length; i++)
            {
                VaultResolutionItem? resolution = _resolutions[i] ?? defaultResolution;
                if (!_items[i].TryApplyTo(ref liveVault, resolution, algorithm))
                {
                    return resolution!;
                }
            }

            return liveVault.GetSnapshot(new RefSigner(algorithm, signer));
        }
    }

    public static Builder Start(ValidatedVaultDataSnapshot baseUnvalidatedVault, ImmutableList<VaultConflictItem> items)
    {
        return new(baseUnvalidatedVault, items);
    }
}