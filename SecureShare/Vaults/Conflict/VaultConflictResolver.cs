using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using VaettirNet.SecureShare.Secrets;

namespace VaettirNet.SecureShare.Vaults.Conflict;

public class VaultConflictResolver
{
    private readonly VaultCryptographyAlgorithm _algorithm;

    public VaultConflictResolver(VaultCryptographyAlgorithm algorithm)
    {
        _algorithm = algorithm;
    }
    
    public VaultConflictResult Resolve(ValidatedVaultDataSnapshot original, ValidatedVaultDataSnapshot? remote, ValidatedVaultDataSnapshot local)
    {
        if (remote is not { } remoteValue)
        {
            return ResolveTwoNoConflict(original, local);
        }

        if (original.Version == remoteValue.Version)
        {
            if (original.Version == local.Version)
            {
                return new VaultConflictResult(remoteValue, []);
            }

            return ResolveTwoNoConflict(remoteValue, local);
        }

        return ResolveThreeWayConflict(original, remoteValue, local);
    }

    public bool TryAutoResolveConflicts(VaultConflictResult result, RefSigner signer, out ValidatedVaultDataSnapshot data)
    {
        LiveVaultData liveVault = LiveVaultData.FromSnapshot(result.BaseVault);
        foreach (VaultConflictItem? item in result.Items)
        {
            if (!item.TryGetAutoResolution(out VaultResolutionItem? resolution))
            {
                data = default;
                return false;
            }

            if (!item.TryApplyTo(ref liveVault, resolution, _algorithm))
            {
                data = default;
                return false;
            }
        }

        data = liveVault.GetSnapshot(signer);
        return true;
    }

    private VaultConflictResult ResolveThreeWayConflict(ValidatedVaultDataSnapshot original, ValidatedVaultDataSnapshot remote, ValidatedVaultDataSnapshot local)
    {
        List<VaultConflictItem> conflicts = [];
        {
            HashSet<Guid> localClientIds = (local.Clients).Select(c => c.ClientId).Concat(local.BlockedClients.Select(c => c.ClientId)).ToHashSet();
            foreach (Guid id in localClientIds)
            {
                OneOf<VaultClientEntry, BlockedVaultClientEntry> localClient = local.GetClientEntry(id);

                if (remote.TryGetClientEntry(id, out OneOf<VaultClientEntry, BlockedVaultClientEntry> remoteClientEntry) && localClient.Equals(remoteClientEntry))
                {
                    // We have the same client entry, we can skip it
                    continue;
                }

                ImmutableList<Validated<ClientModificationRecord>> localModificationRecords = local.GetModificationRecords(id);
                if (!original.TryGetClientEntry(id, out OneOf<VaultClientEntry, BlockedVaultClientEntry> originalClient))
                {
                    // Adding a client is fine
                    localClient.Map(
                        added => conflicts.Add(ClientConflictItem.Added(null, added, localModificationRecords)),
                        blocked => conflicts.Add(ClientConflictItem.Removed(null, blocked, localModificationRecords))
                    );
                    continue;
                }
                
                VaultClientEntry? originalEntry = originalClient.Map(client => client, _ => null);

                if (localClient.Equals(originalClient))
                {
                    // Local has made no changes, nothing to resolve
                    continue;
                }

                if (!remote.TryGetClientEntry(id, out remoteClientEntry))
                {
                    // It's not present in the remote, so we need to update the remote one.
                    localClient.Map(
                        updated => conflicts.Add(ClientConflictItem.Updated(originalEntry, updated, localModificationRecords)),
                        blocked => conflicts.Add(ClientConflictItem.Removed(originalEntry, blocked, localModificationRecords))
                    );
                    continue;
                }

                if (originalClient.Equals(remoteClientEntry))
                {
                    // The remote one is unchanged, so we can just accept our modification
                    localClient.Map(
                        updated => conflicts.Add(ClientConflictItem.Updated(originalEntry, updated, localModificationRecords)),
                        blocked => conflicts.Add(ClientConflictItem.Removed(originalEntry, blocked, localModificationRecords))
                    );
                    continue;
                }

                // There is a three way disagreement, that's unfortunate, add a full conflict
                conflicts.Add(
                        new ClientConflictItem(
                            originalEntry,
                            remoteClientEntry,
                            localClient,
                            remote.GetModificationRecords(id),
                            local.GetModificationRecords(id)
                        )
                    );
            }
        }
        {
            foreach (UntypedVaultSnapshot localVault in local.Vaults)
            {
                if (remote.Vaults.FirstOrDefault(v => v.Id.Equals(localVault.Id)) is { } remoteVault)
                {
                    ResolveVaultConflicts(
                        original.Vaults.FirstOrDefault(v => v.Id.Equals(localVault.Id)),
                        remoteVault,
                        localVault
                    );
                }
                else
                {
                    conflicts.Add(VaultListConflictItem.Added(localVault));
                }
            }

            void ResolveVaultConflicts(UntypedVaultSnapshot? originalVault, UntypedVaultSnapshot remoteVault, UntypedVaultSnapshot localVault)
            {
                HashSet<Guid> secretIds = localVault.Secrets.Select(s => s.Id).Concat(localVault.RemovedSecrets.Select(s => s.Id)).ToHashSet();
                foreach (Guid id in secretIds)
                {
                    OneOf<UntypedSealedSecret, RemovedSecretRecord> localEntry = localVault.GetSecretEntry(id);

                    if (remoteVault.TryGetSecretEntry(id, out OneOf<UntypedSealedSecret, RemovedSecretRecord> remoteEntry) && localEntry.Equals(remoteEntry))
                    {
                        // We have the same secret entry, we can skip it
                        continue;
                    }

                    if (originalVault == null || !originalVault.TryGetSecretEntry(id, out OneOf<UntypedSealedSecret, RemovedSecretRecord> originalEntry))
                    {
                        // Adding a client is fine
                        localEntry.Map(
                            added => conflicts.Add(SecretConflictItem.Added(localVault.Id, null, added)),
                            blocked => conflicts.Add(SecretConflictItem.Removed(localVault.Id, null, blocked))
                        );
                        continue;
                    }
                    UntypedSealedSecret? originalSecret  = originalEntry.Map(client => client, _ => null);

                    if (localEntry.Equals(originalEntry))
                    {
                        // Local has made no changes, nothing to resolve
                        continue;
                    }

                    if (!remoteVault.TryGetSecretEntry(id, out remoteEntry))
                    {
                        // It's not present in the remote, so we need to update the remote one.
                        localEntry.Map(
                            updated => conflicts.Add(SecretConflictItem.Updated(localVault.Id, originalSecret, updated)),
                            blocked => conflicts.Add(SecretConflictItem.Removed(localVault.Id, originalSecret, blocked))
                        );
                        continue;
                    }

                    if (originalEntry.Equals(remoteEntry))
                    {
                        // The remote one is unchanged, so we can just accept our modification
                        localEntry.Map(
                            updated => conflicts.Add(SecretConflictItem.Updated(localVault.Id, originalSecret, updated)),
                            blocked => conflicts.Add(SecretConflictItem.Removed(localVault.Id, originalSecret, blocked))
                        );
                        continue;
                    }

                    // There is a three way disagreement, that's unfortunate, add a full conflict
                    conflicts.Add(
                        new SecretConflictItem(
                            localVault.Id,
                            originalSecret,
                            remoteEntry,
                            localEntry
                        )
                    );
                }
            }
        }

        return new VaultConflictResult(remote, conflicts.ToImmutableList());
    }

    private VaultConflictResult ResolveTwoNoConflict(ValidatedVaultDataSnapshot original, ValidatedVaultDataSnapshot local)
    {
        if (original.Version <= local.Version)
        {
            return new VaultConflictResult(local, []);
        }

        throw new ArgumentException("Original is higher version than local", nameof(original));
    }
}