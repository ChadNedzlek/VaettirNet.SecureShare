using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

public class VaultDataSnapshot
{
    public readonly ImmutableList<VaultClientEntry> Clients;
    public readonly ImmutableList<BlockedVaultClientEntry> BlockedClients;
    public readonly ImmutableList<Signed<ClientModificationRecord>> ClientModificications;
}

public class VaultIdentifier
{
    public readonly string Name;
    public readonly string AttributeType;
    public readonly string ProtectedType;

    public VaultIdentifier(string attributeType, string protectedType) : this(attributeType + '|' + protectedType, attributeType, protectedType)
    {
    }

    public VaultIdentifier(string name, string attributeType, string protectedType)
    {
        Name = name;
        AttributeType = attributeType;
        ProtectedType = protectedType;
    }
}

public class VaultData
{
    private readonly List<VaultClientEntry> _clients;
    private readonly List<BlockedVaultClientEntry> _blockedClients;
    private readonly List<Signed<ClientModificationRecord>> _modificationRecords; 
    private readonly Dictionary<(Type, Type), TypedVault> _vaults;
    private readonly ReadOnlyMemory<byte> _manifestSignature;

    public VaultData(
        IEnumerable<VaultClientEntry>? clients = null,
        IEnumerable<BlockedVaultClientEntry>? blockedClients = null,
        IEnumerable<TypedVault>? vaults = null,
        IEnumerable<Signed<ClientModificationRecord>>? modificationRecords = null,
        ReadOnlyMemory<byte> manifestSignature = default)
    {
        _clients = clients?.ToList() ?? [];
        _blockedClients = blockedClients?.ToList() ?? [];
        _vaults = vaults?.ToDictionary(v => (v.AttributeType, v.ProtectedType)) ?? [];
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

    public void UpdateVault(TypedVault vault)
    {
        _vaults[(vault.AttributeType, vault.ProtectedType)] = vault;
    }

    public TypedVault? GetStoreOrDefault<TAttribute, TProtected>()
        where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute>
        where TProtected : IBinarySerializable<TProtected>
    {
        return _vaults.GetValueOrDefault((typeof(TAttribute), typeof(TProtected)));
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
        AppendCount(hasher, _clients.Count);
        Span<byte> guid = stackalloc byte[16];
        foreach (var client in _clients)
        {
            client.ClientId.TryWriteBytes(guid);
            hasher.AppendData(guid);
        }
        
        AppendCount(hasher, _blockedClients.Count);
        foreach (var client in _blockedClients)
        {
            client.ClientId.TryWriteBytes(guid);
            hasher.AppendData(guid);
        }
        void AppendCount(IncrementalHash h, int count)
        {
            h.AppendData(MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref count, 1)));
        }

        Span<byte> hash = stackalloc byte[hasher.HashLengthInBytes];
        hasher.TryGetHashAndReset(hash, out int hashBytesWritten);
        return withHash(hash[..hashBytesWritten]);
    }

    public void AddModificationRecord(Signed<ClientModificationRecord> record)
    {
        _modificationRecords.Add(record);
    }
}