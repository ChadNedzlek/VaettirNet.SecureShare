using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

namespace VaettirNet.SecureShare.Vaults.Conflict;

public class PartialVaultConflictResolution
{
    private readonly ValidatedVaultDataSnapshot _baseVault;
    private readonly ImmutableList<VaultConflictItem> _items;
    private readonly ImmutableArray<VaultResolutionItem?> _resolutions;

    public PartialVaultConflictResolution(ValidatedVaultDataSnapshot baseVault, ImmutableList<VaultConflictItem> items)
    {
        _baseVault = baseVault;
        _items = items;
        _resolutions = [..new VaultResolutionItem[items.Count]];
    }
    
    private PartialVaultConflictResolution(ValidatedVaultDataSnapshot baseVault, ImmutableList<VaultConflictItem> items, ImmutableArray<VaultResolutionItem?> resolutions)
    {
        _baseVault = baseVault;
        _items = items;
        _resolutions = resolutions;
    }

    public PartialVaultConflictResolution WithResolution(VaultConflictItem conflict, VaultResolutionItem resolution)
    {
        return new PartialVaultConflictResolution(
            _baseVault,
            _items,
            _resolutions.SetItem(_items.IndexOf(conflict), resolution));
    }

    public PartialVaultConflictResolution WithAutoResolutions()
    {
        var res = _resolutions.ToBuilder();
        for (var i = 0; i < _items.Count; i++)
        {
            VaultConflictItem item = _items[i];
            if (item.TryGetAutoResolution(out var r))
            {
                res[i] = r;
            }
        }

        return new PartialVaultConflictResolution(
            _baseVault,
            _items,
            res.ToImmutable()
        );
    }

    public bool TryGetNextUnresolved([MaybeNullWhen(false)] out VaultConflictItem conflict)
    {
        for (var i = 0; i < _items.Count; i++)
        {
            if (_resolutions[i] == null)
            {
                conflict = _items[i];
                return true;
            }
        }

        conflict = null;
        return false;
    }

    public Result<ValidatedVaultDataSnapshot, (VaultConflictItem conflict, VaultResolutionItem? resolution)> Apply(
        VaultCryptographyAlgorithm algorithm,
        PrivateClientInfo signer,
        VaultResolutionItem? defaultResolution = null)
    {
        if (defaultResolution is null)
        {
            int i = _resolutions.IndexOf(null);
            if (i >= 0)
            {
                return (_items[i], null);
            }
        }

        LiveVaultData liveVault = LiveVaultData.FromSnapshot(_baseVault);

        for (int i = 0; i < _resolutions.Length; i++)
        {
            VaultResolutionItem resolution = _resolutions[i] ?? defaultResolution!;
            if (!_items[i].TryApplyTo(ref liveVault, resolution, algorithm))
            {
                return (_items[i], resolution);
            }
        }

        return liveVault.GetSnapshot(new RefSigner(algorithm, signer));
    }
}