using System.Diagnostics.CodeAnalysis;
using VaettirNet.SecureShare.Common;
using VaettirNet.SecureShare.Crypto;
using VaettirNet.SecureShare.Secrets;

namespace VaettirNet.SecureShare.Vaults.Conflict;

public class SecretConflictItem : VaultConflictItem
{
    public readonly VaultIdentifier VaultKey;
    public readonly UntypedSealedSecret BaseEntry;
    public readonly OneOf<UntypedSealedSecret, RemovedSecretRecord> Remote;
    public readonly OneOf<UntypedSealedSecret, RemovedSecretRecord> Local;
    
    public SecretConflictItem(
        VaultIdentifier vaultKey,
        UntypedSealedSecret baseEntry,
        OneOf<UntypedSealedSecret, RemovedSecretRecord> remote,
        OneOf<UntypedSealedSecret, RemovedSecretRecord> local
    )
    {
        VaultKey = vaultKey;
        BaseEntry = baseEntry;
        Remote = remote;
        Local = local;
    }

    public override bool TryGetAutoResolution([MaybeNullWhen(false)] out VaultResolutionItem resolution)
    {
        resolution = null;
        return false;
    }

    public override bool TryApplyTo(ref LiveVaultData liveVault, VaultResolutionItem resolution, VaultCryptographyAlgorithm algorithm)
    {
        LiveVaultData data = liveVault;
        
        if (resolution == VaultResolutionItem.AcceptLocal)
        {
            Apply(Local);
            return true;
        }

        if (resolution == VaultResolutionItem.AcceptRemote)
        {
            Apply(Remote);
            return true;
        }

        return false;

        void Apply(OneOf<UntypedSealedSecret, RemovedSecretRecord> target)
        {
            target.Map(
                modifiedOrAdded => data.SetSecret(VaultKey, modifiedOrAdded),
                deleted => data.RemoveSecret(VaultKey, deleted.Id)
            );
        }
    }
    
    public class NoConflictItem : VaultConflictItem
    {
        public readonly VaultIdentifier VaultKey;
        public readonly UntypedSealedSecret BaseEntry;
        public readonly OneOf<UntypedSealedSecret, RemovedSecretRecord> Updated;

        public NoConflictItem(VaultIdentifier vaultKey, UntypedSealedSecret baseEntry, OneOf<UntypedSealedSecret, RemovedSecretRecord> updated)
        {
            VaultKey = vaultKey;
            BaseEntry = baseEntry;
            Updated = updated;
        }

        public override bool TryGetAutoResolution([MaybeNullWhen(false)] out VaultResolutionItem resolution)
        {
            resolution = VaultResolutionItem.AcceptLocal;
            return true;
        }

        public override bool TryApplyTo(ref LiveVaultData liveVault, VaultResolutionItem resolution, VaultCryptographyAlgorithm algorithm)
        {
            LiveVaultData data = liveVault;
            Updated.Map(
                addedOrUpdated => data.SetSecret(VaultKey, addedOrUpdated),
                removed => data.RemoveSecret(VaultKey, removed.Id)
            );
            return true;
        }
    }

    public static NoConflictItem Added(VaultIdentifier vaultKey, UntypedSealedSecret baseEntry, UntypedSealedSecret newEntry) =>
        new(vaultKey, baseEntry, newEntry);
    public static NoConflictItem Updated(VaultIdentifier vaultKey, UntypedSealedSecret baseEntry, UntypedSealedSecret newEntry) =>
        new(vaultKey, baseEntry, newEntry);
    public static NoConflictItem Removed(VaultIdentifier vaultKey, UntypedSealedSecret baseEntry, RemovedSecretRecord newEntry) =>
        new(vaultKey, baseEntry, newEntry);
}