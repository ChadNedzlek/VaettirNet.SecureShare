using System;
using System.Buffers.Text;
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
    private readonly ReadOnlyMemory<byte> _manifestSignature;

    public LiveVaultData(
        IEnumerable<VaultClientEntry>? clients = null,
        IEnumerable<BlockedVaultClientEntry>? blockedClients = null,
        IEnumerable<UntypedVaultSnapshot>? vaults = null,
        IEnumerable<Signed<ClientModificationRecord>>? modificationRecords = null,
        ReadOnlyMemory<byte> manifestSignature = default)
    {
        _clients = clients?.ToList() ?? [];
        _blockedClients = blockedClients?.ToList() ?? [];
        _vaults = vaults?.ToList() ?? [];
        _modificationRecords = modificationRecords?.ToList() ?? [];
        _manifestSignature = manifestSignature;
    }

    public IEnumerable<VaultClientEntry> Clients => _clients.AsReadOnly();

    public void AddClient(VaultClientEntry client)
    {
        _clients.Add(client);
    }

    public void BlockClient(BlockedVaultClientEntry blocked)
    {
        _clients.RemoveAll(c => c.ClientId == blocked.ClientId);
        _blockedClients.Add(blocked);
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

    public UntypedVaultSnapshot GetStoreOrDefault<TAttribute, TProtected>()
        where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute>
        where TProtected : IBinarySerializable<TProtected>
    {
        return _vaults.First(v => v.Id.Equals(VaultIdentifier.Create<TAttribute, TProtected>()));
    }
    
    public UntypedVaultSnapshot GetStoreOrDefault<TAttribute, TProtected>(string? name)
        where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute>
        where TProtected : IBinarySerializable<TProtected>
    {
        return _vaults.FirstOrDefault(v => v.Id.Equals(VaultIdentifier.Create<TAttribute, TProtected>(name))) ??
            new UntypedVaultSnapshot(VaultIdentifier.Create<TAttribute, TProtected>(name), [], []);
    }

    public bool HasPublicKey(Guid clientId)
    {
        return _clients.Any(c => c.ClientId == clientId);
    }

    public ReadOnlyMemory<byte> GetPublicKey(Guid clientId)
    {
        return _clients.FirstOrDefault(c => c.ClientId == clientId)?.EncryptionKey ?? throw new KeyNotFoundException();
    }

    public T WithManifestHash<T>(Func<Span<byte>, T> withHash)
    {
        using IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        AppendInt(hasher, _clients.Count);
        Span<byte> buffer = stackalloc byte[1000];
        foreach (var client in _clients)
        {
            AppendGuid(hasher, client.ClientId, buffer);
        }
        
        AppendInt(hasher, _blockedClients.Count);
        foreach (var client in _blockedClients)
        {
            AppendGuid(hasher, client.ClientId, buffer);
        }

        AppendInt(hasher, _vaults.Count);
        foreach (UntypedVaultSnapshot vault in _vaults)
        {
            AppendString(hasher, vault.Id.Name, buffer);
            AppendString(hasher, vault.Id.AttributeTypeName, buffer);
            AppendString(hasher, vault.Id.ProtectedTypeName, buffer);
            
            AppendInt(hasher, vault.Secrets.Count);
            foreach (UntypedSealedSecret secret in vault.Secrets)
            {
                AppendGuid(hasher, secret.Id, buffer);
            }
            
            AppendInt(hasher, vault.RemovedSecrets.Count);
            foreach (Signed<RemovedSecretRecord> secret in vault.RemovedSecrets)
            {
                AppendGuid(hasher, secret.DangerousGetPayload().Id, buffer);
            }
        }

        Span<byte> hash = stackalloc byte[hasher.HashLengthInBytes];
        hasher.TryGetHashAndReset(hash, out int hashBytesWritten);
        return withHash(hash[..hashBytesWritten]);
        
        static void AppendGuid(IncrementalHash h, Guid value, Span<byte> buffer)
        {
            value.TryWriteBytes(buffer);
            h.AppendData(buffer[..16]);
        }
        
        static void AppendInt(IncrementalHash h, int count)
        {
            h.AppendData(MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref count, 1)));
        }
        
        static void AppendString(IncrementalHash h, string value, Span<byte> buffer)
        {
            AppendInt(h, value.Length);
            var len = Encoding.UTF8.GetBytes(value, buffer);
            h.AppendData(buffer[..len]);
        }
    }

    public void AddModificationRecord(Signed<ClientModificationRecord> record)
    {
        _modificationRecords.Add(record);
    }

    public VaultDataSnapshot GetSignedSnapshot(Signer signer)
    {
        return new VaultDataSnapshot
        {
            Clients = _clients.ToImmutableList(),
            BlockedClients = _blockedClients.ToImmutableList(),
            ClientModificications = _modificationRecords.ToImmutableList(),
            Vaults = _vaults.ToImmutableList(),
            ManifestSignature = WithManifestHash(s => signer.Algorithm.GetSignatureForByteArray(signer.Keys, signer.Password.Span, s)),
        };
    }

    public static LiveVaultData FromSnapshot(VaultDataSnapshot snapshot)
    {
        return new LiveVaultData(
            snapshot.Clients,
            snapshot.BlockedClients,
            snapshot.Vaults,
            snapshot.ClientModificications,
            snapshot.ManifestSignature
        );
    }
}