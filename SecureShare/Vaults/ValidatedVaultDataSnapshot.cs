using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using VaettirNet.SecureShare.Sync;

namespace VaettirNet.SecureShare.Vaults;

public readonly struct ValidatedVaultDataSnapshot
{
    private readonly Validated<UnvalidatedVaultDataSnapshot> _snapshot;
    private readonly ImmutableList<Validated<ClientModificationRecord>> _modificationRecords;

    internal ValidatedVaultDataSnapshot(Validated<UnvalidatedVaultDataSnapshot> snapshot)
    {
        _snapshot = snapshot;
        _modificationRecords = snapshot.Value.ClientModifications?.Select(Validated.AssertValid).ToImmutableList() ?? [];
    }

    public bool IsEmpty => _snapshot.IsEmpty;
    public ImmutableSortedSet<VaultClientEntry> Clients => _snapshot.Value.Clients ?? [];
    public ImmutableSortedSet<BlockedVaultClientEntry> BlockedClients => _snapshot.Value.BlockedClients ?? [];
    public ImmutableList<Validated<ClientModificationRecord>> ClientModifications => _modificationRecords;
    public ImmutableSortedSet<UntypedVaultSnapshot> Vaults => _snapshot.Value.Vaults ?? [];
    public uint Version => _snapshot.Value.Version;

    public bool TryGetClientEntry(Guid id, out OneOf<VaultClientEntry, BlockedVaultClientEntry> result)
    {
        var entry = Clients.FirstOrDefault(c => c.ClientId == id);
        if (entry != null)
        {
            result = entry;
            return true;
        }

        var blocked = BlockedClients.FirstOrDefault(c => c.ClientId == id);
        if (blocked != null)
        {
            result = blocked;
            return true;
        }

        result = default;
        return false;
    }
    public OneOf<VaultClientEntry, BlockedVaultClientEntry> GetClientEntry(Guid id)
    {
        if (TryGetClientEntry(id, out OneOf<VaultClientEntry, BlockedVaultClientEntry> value)) return value;
        throw new KeyNotFoundException();
    }

    public ImmutableList<Validated<ClientModificationRecord>> GetModificationRecords(Guid clientId)
    {
        return _modificationRecords?.Where(c => c.Value.Client == clientId).ToImmutableList() ?? [];
    }

    public bool TryGetSignerPublicInfo(out PublicClientInfo signer)
    {
        VaultClientEntry? info = null;
        if (_snapshot.Value.Clients is {} clients)
        {
            foreach (VaultClientEntry c in clients)
            {
                if (c.ClientId == _snapshot.Signer)
                {
                    info = c;
                    break;
                }
            }
        }

        if (info == null)
        {
            signer = default;
            return false;
        }

        signer = info.PublicInfo;
        return true;
    }

    public static bool TryValidate(Signed<UnvalidatedVaultDataSnapshot> snapshot, ReadOnlySpan<byte> publicKey, VaultCryptographyAlgorithm algorithm, out ValidatedVaultDataSnapshot output)
    {
        if (!Validated.TryValidate(snapshot, publicKey, algorithm, out var validated))
        {
            output = default;
            return false;
        }

        output = new ValidatedVaultDataSnapshot(validated);
        return true;
    }

    public static ValidatedVaultDataSnapshot Validate(Signed<UnvalidatedVaultDataSnapshot> snapshot, ReadOnlySpan<byte> publicKey, VaultCryptographyAlgorithm algorithm)
    {
        if (!TryValidate(snapshot, publicKey, algorithm, out var validated))
        {
            throw new InvalidVaultException(snapshot.DangerousGetPayload(), "Invalidly signed vault");
        }

        return validated;
    }

    internal static ValidatedVaultDataSnapshot AssertValid(Signed<UnvalidatedVaultDataSnapshot> snapshot)
    {
        return new ValidatedVaultDataSnapshot(Validated.AssertValid(snapshot));
    }

    public static implicit operator UnvalidatedVaultDataSnapshot(ValidatedVaultDataSnapshot validated) => validated._snapshot.Value;
    public static implicit operator Signed<UnvalidatedVaultDataSnapshot>(ValidatedVaultDataSnapshot validated) => validated._snapshot.Signed;
}

public static class ValidatedVaultDataSnapshotExtensions
{
    public static bool TryValidate(this Signed<UnvalidatedVaultDataSnapshot> snapshot, VaultCryptographyAlgorithm algorithm, out ValidatedVaultDataSnapshot validated)
    {
        UnvalidatedVaultDataSnapshot unvalidated = snapshot.DangerousGetPayload();
        foreach (var client in unvalidated.Clients ?? [])
        {
            if (client.ClientId == snapshot.Signer)
            {
                return ValidatedVaultDataSnapshot.TryValidate(snapshot, client.SigningKey.Span, algorithm, out validated);
            }
        }

        validated = default;
        return false;
    }
    
    public static ValidatedVaultDataSnapshot Validate(this Signed<UnvalidatedVaultDataSnapshot> snapshot, VaultCryptographyAlgorithm algorithm)
    {
        UnvalidatedVaultDataSnapshot unvalidated = snapshot.DangerousGetPayload();
        foreach (var client in unvalidated.Clients ?? [])
        {
            if (client.ClientId == snapshot.Signer)
            {
                return ValidatedVaultDataSnapshot.Validate(snapshot, client.SigningKey.Span, algorithm);
            }
        }

        throw new InvalidVaultException(unvalidated, "No appropriate signer found");
    }
}