using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

public class VaultData
{
    private readonly List<VaultClientEntry> _clients;
    private readonly Dictionary<(Type, Type), List<object>> _typedStores;

    public VaultData() : this([], [])
    {
    }

    public VaultData(Dictionary<(Type, Type), List<object>> typedStores) : this([], typedStores)
    {
    }

    public VaultData(List<VaultClientEntry> clients) : this(clients, [])
    {
    }

    public VaultData(List<VaultClientEntry> clients, Dictionary<(Type, Type), List<object>> typedStores)
    {
        _clients = clients;
        _typedStores = typedStores;
    }

    public IEnumerable<VaultClientEntry> Clients => _clients.AsReadOnly();

    public void AddClient(VaultClientEntry client)
    {
        _clients.Add(client);
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

    public void AddStore<TAttribute, TProtected>(IEnumerable<SealedSecretValue<TAttribute, TProtected>> store) where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute> where TProtected : IBinarySerializable<TProtected>
    {
        _typedStores[(typeof(TAttribute), typeof(TProtected))] = store.ToList<object>();
    }

    public IEnumerable<SealedSecretValue<TAttribute, TProtected>>? GetStoreOrDefault<TAttribute, TProtected>()
        where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute>
        where TProtected : IBinarySerializable<TProtected>
    {
        List<object> list;
        if (!_typedStores.TryGetValue((typeof(TAttribute), typeof(TProtected)), out list!))
        {
            return null;
        }

        return list.Cast<SealedSecretValue<TAttribute, TProtected>>();
    }

    public bool HasPublicKey(Guid clientId)
    {
        return _clients.Any(c => c.ClientId == clientId);
    }

    public ReadOnlyMemory<byte> GetPublicKey(Guid clientId)
    {
        return _clients.FirstOrDefault(c => c.ClientId == clientId)?.PublicKey ?? throw new KeyNotFoundException();
    }
}