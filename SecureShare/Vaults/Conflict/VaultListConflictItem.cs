using System;
using System.Diagnostics.CodeAnalysis;
using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.SecureShare.Vaults.Conflict;

public class VaultListConflictItem : VaultConflictItem
{
    public readonly UntypedVaultSnapshot BaseEntry;
    public readonly UntypedVaultSnapshot Local;
    public readonly UntypedVaultSnapshot Remote;

    public VaultListConflictItem(UntypedVaultSnapshot baseEntry, UntypedVaultSnapshot local, UntypedVaultSnapshot remote)
    {
        BaseEntry = baseEntry;
        Local = local;
        Remote = remote;
    }

    public override bool TryGetAutoResolution([MaybeNullWhen(false)] out VaultResolutionItem resolution)
    {
        if ((Remote == null && BaseEntry == null && Local is not null) || (BaseEntry is not null && Remote is not null && Local is null))
        {
            resolution = VaultResolutionItem.AcceptLocal;
            return true;
        }
        
        if ((Local == null && BaseEntry == null && Remote is not null) || (BaseEntry is not null && Local is not null && Remote is null))
        {
            resolution = VaultResolutionItem.AcceptRemote;
            return true;
        }

        resolution = null;
        return false;
    }

    public override bool TryApplyTo(ref LiveVaultData liveVault, VaultResolutionItem resolution, VaultCryptographyAlgorithm algorithm)
    {
        if (resolution == VaultResolutionItem.AcceptLocal)
        {
            NewFunction(liveVault, Local);
            return true;
        }
        
        if (resolution == VaultResolutionItem.AcceptRemote)
        {
            NewFunction(liveVault, Remote);
            return true;
        }

        return false;

        void NewFunction(LiveVaultData vault, UntypedVaultSnapshot store)
        {
            if (BaseEntry == null)
            {
                vault.AddStore(store ?? throw new ArgumentException("Both candidates are null", nameof(resolution)));
            }
            else
            {
                if (store != null)
                {
                    throw new ArgumentException("Both candidates are present, must merge each secret", nameof(resolution));
                }
                vault.RemoveStore(BaseEntry.Id);
            }
        }
    }

    public static VaultListConflictItem Added(UntypedVaultSnapshot added) => new(null, added, null);
    public static VaultListConflictItem Removed(UntypedVaultSnapshot removed) => new(removed, null, null);
}