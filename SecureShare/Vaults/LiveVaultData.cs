using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

public class LiveVaultData
{
    private readonly uint _baseVersion;
    private readonly List<VaultClientEntry> _clients;
    private readonly List<BlockedVaultClientEntry> _blockedClients;
    private readonly List<Validated<ClientModificationRecord>> _modificationRecords; 
    private readonly List<UntypedVaultSnapshot> _vaults;

    public LiveVaultData(
        IEnumerable<VaultClientEntry>? clients = null,
        IEnumerable<BlockedVaultClientEntry>? blockedClients = null,
        IEnumerable<UntypedVaultSnapshot>? vaults = null,
        ImmutableList<Validated<ClientModificationRecord>>? modificationRecords = null,
        uint baseVersion = 0
    )
    {
        _baseVersion = baseVersion;
        _clients = clients?.ToList() ?? [];
        _blockedClients = blockedClients?.ToList() ?? [];
        _vaults = vaults?.ToList() ?? [];
        _modificationRecords = modificationRecords?.ToList() ?? [];
    }

    public IEnumerable<VaultClientEntry> Clients => _clients.AsReadOnly();

    public void UpdateClient(VaultClientEntry client, Signer signer)
    {
        int existingIndex = _clients.FindIndex(i => i.ClientId == client.ClientId);
        if (existingIndex == -1)
        {
            AddClient(client, signer);
            return;
        }

        VaultClientEntry existing = _clients[existingIndex];
        Validated<ClientModificationRecord> record = signer.Algorithm.Sign(
            new ClientModificationRecord(ClientAction.KeyChange, client.ClientId, existing.SigningKey, existing.EncryptionKey, signer.Keys.ClientId),
            signer.Keys
        );
        UpdateClient(client, [record]);
    }

    public void UpdateClient(VaultClientEntry client, IReadOnlyList<Validated<ClientModificationRecord>> records)
    {
        int existingIndex = _clients.FindIndex(i => i.ClientId == client.ClientId);
        _clients[existingIndex] = client;
        _modificationRecords.AddRange(records);
    }

    public void AddClient(VaultClientEntry client, RefSigner signer)
    {
        _clients.Add(client);
        _modificationRecords.Add(
            signer.Algorithm.Sign(
                new ClientModificationRecord(ClientAction.Added, client.ClientId, default, default, signer.Keys.ClientId),
                signer.Keys
            )
        );
    }

    public void AddClient(VaultClientEntry client, ImmutableList<Validated<ClientModificationRecord>> records, VaultCryptographyAlgorithm algorithm)
    {
        Signed<ClientModificationRecord> record = records[^1];
        if (record.Signer != client.Authorizer)
        {
            throw new ArgumentException("Modification record signer does not match client", nameof(record));
        }
        
        if (!TryGetClient(record.Signer, out VaultClientEntry? signer)){
            throw new ArgumentException("Signature is not present in vault", nameof(record));
        }

        if (!algorithm.TryValidate(record, signer.PublicInfo, out Validated<ClientModificationRecord> payload))
        {
            throw new ArgumentException("Signature is invalid", nameof(record));
        }

        if (payload.Value.Action != ClientAction.Added)
        {
            throw new ArgumentException("Record is not an add record", nameof(record));
        }

        if (payload.Value.Client != client.ClientId)
        {
            throw new ArgumentException("Record target does not match client", nameof(record));
        }

        _clients.Add(client);
        _modificationRecords.AddRange(records);
    }

    public void BlockClient(BlockedVaultClientEntry blocked, ImmutableList<Validated<ClientModificationRecord>> records, VaultCryptographyAlgorithm algorithm)
    {
        Signed<ClientModificationRecord> record = records[^1];
        if (!TryGetClient(record.Signer, out VaultClientEntry? signer)){
            throw new ArgumentException("Signature is not present in vault", nameof(record));
        }

        if (!algorithm.TryValidate(record, signer.PublicInfo, out Validated<ClientModificationRecord> payload))
        {
            throw new ArgumentException("Signature is invalid", nameof(record));
        }

        if (payload.Value.Action != ClientAction.Added)
        {
            throw new ArgumentException("Record is not an add record", nameof(record));
        }

        if (payload.Value.Client != blocked.ClientId)
        {
            throw new ArgumentException("Record target does not match client", nameof(record));
        }
        
        _blockedClients.Add(blocked);
        _modificationRecords.AddRange(records);
    }
    
    public void BlockClient(BlockedVaultClientEntry blocked, Signer signer)
    {
        _clients.RemoveAll(c => c.ClientId == blocked.ClientId);
        _blockedClients.Add(blocked);
        _modificationRecords.Add(
            signer.Algorithm.Sign(
                new ClientModificationRecord(ClientAction.Blocked, blocked.ClientId, default, default, signer.Keys.ClientId),
                signer.Keys
            )
        );
    }

    public ImmutableArray<Validated<ClientModificationRecord>> GetModificationRecords(Guid clientId)
    {
        return _modificationRecords.Where(r => r.Value.Client == clientId).ToImmutableArray();
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

    public IEnumerable<VaultIdentifier> GetVaultIds()
    {
        return _vaults.Select(v => v.Id);
    }

    public OpenVaultReader<TAttribute, TProtected> GetStoreOrDefault<TAttribute, TProtected>(string? name = null)
        where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute>
        where TProtected : IBinarySerializable<TProtected>
    {
        VaultIdentifier id = VaultIdentifier.Create<TAttribute, TProtected>(name);
        UntypedVaultSnapshot snapshot = _vaults.FirstOrDefault(v => v.Id.Equals(id)) ?? new UntypedVaultSnapshot(id, [], []);
        return OpenVaultReader<TAttribute, TProtected>.FromSnapshot(snapshot);
    }
    
    public void AddStore(UntypedVaultSnapshot snapshot)
    {
        if (_vaults.Any(v => v.Id.Equals(snapshot.Id)))
        {
            throw new ArgumentException("Vault already exists", nameof(snapshot));
        }
        _vaults.Add(snapshot);
    }
    
    public void RemoveStore(VaultIdentifier id)
    {
        _vaults.RemoveAll(v => v.Id.Equals(id));
    }
    
    public void SetSecret(VaultIdentifier id, UntypedSealedSecret secret)
    {
        int index = _vaults.FindIndex(v => v.Id.Equals(id));
        if (index >= 0)
        {
            _vaults[index] = WithUpdatedSecret(_vaults[index], secret);
        }
        else
        {
            _vaults.Add(new UntypedVaultSnapshot(id, [secret], []));
        }

        static UntypedVaultSnapshot WithUpdatedSecret(UntypedVaultSnapshot snapshot, UntypedSealedSecret secret)
        {
            ImmutableSortedSet<UntypedSealedSecret> list = snapshot.Secrets;
            for (int i = 0; i < list.Count; i++)
            {
                UntypedSealedSecret inVault = list[i];
                if (inVault.Id == secret.Id)
                {
                    return new UntypedVaultSnapshot(snapshot.Id, list.Remove(inVault).Add(secret), snapshot.RemovedSecrets);
                }
            }
            return new UntypedVaultSnapshot(snapshot.Id, list.Add(secret), snapshot.RemovedSecrets);
        }

    }

    public void RemoveSecret(VaultIdentifier id, Guid secretId)
    {
        int index = _vaults.FindIndex(v => v.Id.Equals(id));
        if (index >= 0)
        {
            UntypedSealedSecret? secret = _vaults[index].Secrets.FirstOrDefault(s => s.Id == secretId);
            if (secret == null)
                return;
            
            _vaults[index] = new UntypedVaultSnapshot(
                id,
                _vaults[index].Secrets.Where(s => s.Id != secret.Id),
                _vaults[index].RemovedSecrets.Add(new RemovedSecretRecord(secretId, secret.Version, secret.HashBytes))
            );
        }
    }

    public bool HasPublicKey(Guid clientId)
    {
        return _clients.Any(c => c.ClientId == clientId);
    }

    public ReadOnlyMemory<byte> GetPublicKey(Guid clientId)
    {
        return _clients.FirstOrDefault(c => c.ClientId == clientId)?.EncryptionKey ?? throw new KeyNotFoundException();
    }

    public ValidatedVaultDataSnapshot GetSnapshot(RefSigner signer)
    {
        return ValidatedVaultDataSnapshot.AssertValid(signer.Algorithm.Sign(ToUnvalidatedVault(), signer.Keys));
    }

    private UnvalidatedVaultDataSnapshot ToUnvalidatedVault()
    {
        return new UnvalidatedVaultDataSnapshot(
            _clients,
            _blockedClients,
            _modificationRecords.Select(r => r.Signed),
            _vaults,
            _baseVersion + 1
        );
    }

    public static LiveVaultData FromSnapshot(ValidatedVaultDataSnapshot snapshot)
    {
        return new LiveVaultData(
            snapshot.Clients,
            snapshot.BlockedClients,
            snapshot.Vaults,
            snapshot.ClientModifications,
            snapshot.Version
        );
    }
}