using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

public class LiveVaultData
{
    private readonly List<VaultClientEntry> _clients;
    private readonly List<BlockedVaultClientEntry> _blockedClients;
    private readonly List<Signed<ClientModificationRecord>> _modificationRecords; 
    private readonly List<UntypedVaultSnapshot> _vaults;

    public LiveVaultData(
        IEnumerable<VaultClientEntry>? clients = null,
        IEnumerable<BlockedVaultClientEntry>? blockedClients = null,
        IEnumerable<UntypedVaultSnapshot>? vaults = null,
        IEnumerable<Signed<ClientModificationRecord>>? modificationRecords = null)
    {
        _clients = clients?.ToList() ?? [];
        _blockedClients = blockedClients?.ToList() ?? [];
        _vaults = vaults?.ToList() ?? [];
        _modificationRecords = modificationRecords?.ToList() ?? [];
    }

    public IEnumerable<VaultClientEntry> Clients => _clients.AsReadOnly();

    public void UpdateClient(VaultClientEntry client, Signer signer)
    {
    }

    public void AddClient(VaultClientEntry client, RefSigner signer)
    {
        _clients.Add(client);
        _modificationRecords.Add(
            signer.Algorithm.Sign(
                new ClientModificationRecord(ClientAction.Added, client.ClientId, default, default, signer.Keys.ClientId),
                signer.Keys,
                signer.Password
            )
        );
    }

    public void BlockClient(BlockedVaultClientEntry blocked, Signer signer)
    {
        _clients.RemoveAll(c => c.ClientId == blocked.ClientId);
        _blockedClients.Add(blocked);
        _modificationRecords.Add(
            signer.Algorithm.Sign(
                new ClientModificationRecord(ClientAction.Blocked, blocked.ClientId, default, default, signer.Keys.ClientId),
                signer.Keys,
                signer.Password.Span
            )
        );
    }

    public ImmutableArray<Signed<ClientModificationRecord>> GetModificationRecords(Guid clientId)
    {
        return _modificationRecords.Where(r => r.DangerousGetPayload().Client == clientId).ToImmutableArray();
    }

    public bool TryGetClient(Guid id, [MaybeNullWhen(false)] out VaultClientEntry client)
    {
        return (client = _clients.FirstOrDefault(c => c.ClientId == id)) is not null;
    }

    public VaultClientEntry GetClient(Guid id)
    {
        VaultClientEntry? client = _clients.FirstOrDefault(c => c.ClientId == id);
        if (client is null) throw new KeyNotFoundException();

        return client;
    }

    public void UpdateVault(UntypedVaultSnapshot vault)
    {
        _vaults.RemoveAll(v => v.Id.Equals(vault.Id));
        _vaults.Add(vault);
    }
    
    public OpenVault<TAttribute, TProtected> GetStoreOrDefault<TAttribute, TProtected>(string? name = null)
        where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute>
        where TProtected : IBinarySerializable<TProtected>
    {
        var id = VaultIdentifier.Create<TAttribute, TProtected>(name);
        var snapshot = _vaults.FirstOrDefault(v => v.Id.Equals(id)) ?? new UntypedVaultSnapshot(id, [], []);
        return OpenVault<TAttribute, TProtected>.FromSnapshot(snapshot);
    }

    public bool HasPublicKey(Guid clientId)
    {
        return _clients.Any(c => c.ClientId == clientId);
    }

    public ReadOnlyMemory<byte> GetPublicKey(Guid clientId)
    {
        return _clients.FirstOrDefault(c => c.ClientId == clientId)?.EncryptionKey ?? throw new KeyNotFoundException();
    }

    public VaultDataSnapshot GetSnapshot()
    {
        return new VaultDataSnapshot(
            _clients,
            _blockedClients,
            _modificationRecords,
            _vaults
        );
    }

    public static LiveVaultData FromSnapshot(VaultDataSnapshot snapshot)
    {
        return new LiveVaultData(
            snapshot.Clients,
            snapshot.BlockedClients,
            snapshot.Vaults,
            snapshot.ClientModifications
        );
    }
}