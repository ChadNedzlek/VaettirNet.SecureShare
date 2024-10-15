using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

public class TypedVault
{
    public Type AttributeType { get; }
    public Type ProtectedType { get; }

    public ImmutableArray<object> SealedSecrets;
    public ImmutableDictionary<Guid, ReadOnlyMemory<byte>> DeletedSecrets;

    public TypedVault(Type attributeType, Type protectedType, IEnumerable<object>? sealedSecrets = null, ImmutableDictionary<Guid, ReadOnlyMemory<byte>>? deletedSecrets = null)
    {
        AttributeType = attributeType;
        ProtectedType = protectedType;
        SealedSecrets = sealedSecrets?.ToImmutableArray() ?? [];
        DeletedSecrets = deletedSecrets ?? ImmutableDictionary<Guid, ReadOnlyMemory<byte>>.Empty;
    }
}

public class VaultData
{
    private readonly List<VaultClientEntry> _clients;
    private readonly List<BlockedVaultClientEntry> _blockedClients;
    private readonly Dictionary<(Type, Type), TypedVault> _vaults;

    public VaultData(
        IEnumerable<VaultClientEntry>? clients = null,
        IEnumerable<BlockedVaultClientEntry>? blockedClients = null,
        IEnumerable<TypedVault>? vaults = null)
    {
        _clients = clients?.ToList() ?? [];
        _blockedClients = blockedClients?.ToList() ?? [];
        _vaults = vaults?.ToDictionary(v => (v.AttributeType, v.ProtectedType)) ?? [];
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
}