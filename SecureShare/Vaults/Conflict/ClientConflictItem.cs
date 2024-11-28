using System;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using VaettirNet.SecureShare.Common;
using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.SecureShare.Vaults.Conflict;

public class ClientConflictItem : VaultConflictItem
{
    public readonly Guid Id;
    public readonly string Description;
    public readonly VaultClientEntry BaseEntry;
    public readonly OneOf<VaultClientEntry, BlockedVaultClientEntry> Remote;
    public readonly OneOf<VaultClientEntry, BlockedVaultClientEntry> Local;
    public readonly ImmutableList<Validated<ClientModificationRecord>> RemoteModifications;
    public readonly ImmutableList<Validated<ClientModificationRecord>> LocalModifications;

    public ClientConflictItem(
        VaultClientEntry baseEntry,
        OneOf<VaultClientEntry, BlockedVaultClientEntry> remote,
        OneOf<VaultClientEntry, BlockedVaultClientEntry> local,
        ImmutableList<Validated<ClientModificationRecord>> remoteModifications,
        ImmutableList<Validated<ClientModificationRecord>> localModifications
    )
    {
        BaseEntry = baseEntry;
        Remote = remote;
        Local = local;
        RemoteModifications = remoteModifications;
        LocalModifications = localModifications;
        Id = BaseEntry?.ClientId ?? Remote.Map<Guid>(c => c.ClientId, b => b.ClientId);
        Description = BaseEntry?.Description ?? Remote.Map<string>(c => c.Description, b => b.Description);
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
            Accept(data, algorithm, Local, LocalModifications);
            return true;
        }

        if (resolution == VaultResolutionItem.AcceptRemote)
        {
            Accept(data, algorithm, Remote, RemoteModifications);
            return true;
        }

        return false;
    }

    private static void Accept(
        LiveVaultData liveVaultData,
        VaultCryptographyAlgorithm algorithm,
        OneOf<VaultClientEntry, BlockedVaultClientEntry> target,
        ImmutableList<Validated<ClientModificationRecord>> modifications
    )
    {
        Signed<ClientModificationRecord> lastModification = modifications[^1];
        ClientModificationRecord record = algorithm.GetPayload(
            lastModification,
            liveVaultData.GetClient(lastModification.Signer).PublicInfo
        );
        target.Map(
            client =>
            {
                switch (record.Action)
                {
                    case ClientAction.Added:
                        liveVaultData.AddClient(client, modifications, algorithm);
                        break;
                    case ClientAction.KeyChange:
                        liveVaultData.UpdateClient(client, modifications);
                        break;
                    default:
                        throw new ArgumentException("Mismatched record type");
                }
            },
            blocked =>
            {
                switch (record.Action)
                {
                    case ClientAction.Blocked:
                        liveVaultData.BlockClient(blocked, modifications, algorithm);
                        break;
                    default:
                        throw new ArgumentException("Mismatched record type");
                }
            }
        );
    }

    public class NoConflictItem : VaultConflictItem
    {
        public readonly VaultClientEntry BaseEntry;
        public readonly OneOf<VaultClientEntry, BlockedVaultClientEntry> Updated;
        public readonly ImmutableList<Validated<ClientModificationRecord>> Modifications;

        public NoConflictItem(
            VaultClientEntry baseEntry,
            OneOf<VaultClientEntry, BlockedVaultClientEntry> updated,
            ImmutableList<Validated<ClientModificationRecord>> modifications
        )
        {
            BaseEntry = baseEntry;
            Updated = updated;
            Modifications = modifications;
        }

        public override bool TryGetAutoResolution([MaybeNullWhen(false)] out VaultResolutionItem resolution)
        {
            resolution = VaultResolutionItem.AcceptLocal;
            return true;
        }

        public override bool TryApplyTo(ref LiveVaultData liveVault, VaultResolutionItem resolution, VaultCryptographyAlgorithm algorithm)
        {
            Accept(liveVault, algorithm, Updated, Modifications);
            return true;
        }
    }

    public static NoConflictItem Added(VaultClientEntry baseEntry, VaultClientEntry newEntry, ImmutableList<Validated<ClientModificationRecord>> modifications) =>
        new(baseEntry, newEntry, modifications);
    public static NoConflictItem Updated(VaultClientEntry baseEntry, VaultClientEntry newEntry, ImmutableList<Validated<ClientModificationRecord>> modifications) =>
        new(baseEntry, newEntry, modifications);
    public static NoConflictItem Removed(VaultClientEntry baseEntry, BlockedVaultClientEntry newEntry, ImmutableList<Validated<ClientModificationRecord>> modifications) =>
        new(baseEntry, newEntry, modifications);
}