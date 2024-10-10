using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace SecureShare;

public class VaultData
{
    private readonly List<VaultClientEntry> _clients;
    private readonly Dictionary<string, List<string>> _typedStores;

    public VaultData(List<VaultClientEntry> clients, Dictionary<string, List<string>> typedStores)
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

    public void AddStore<TAttribute, TProtected>(IEnumerable<SealedSecretValue<TAttribute, TProtected>> store)
    {
        string key = typeof(TAttribute).FullName + '|' + typeof(TProtected).FullName;
        AddStore(key, store);
    }
    
    public void AddStore<TAttribute, TProtected>(string key, IEnumerable<SealedSecretValue<TAttribute, TProtected>> store)
    {
        SecretSerializer serializer = new();
        _typedStores[key] = store.Select(serializer.Serialize).ToList();
    }

    public IEnumerable<SealedSecretValue<TAttribute, TProtected>>? GetStoreOrDefault<TAttribute, TProtected>()
    {
        string key = typeof(TAttribute).FullName + '|' + typeof(TProtected).FullName;
        return GetStoreOrDefault<TAttribute, TProtected>(key);
    }
    
    public IEnumerable<SealedSecretValue<TAttribute, TProtected>>? GetStoreOrDefault<TAttribute, TProtected>(string key)
    {
        if (!_typedStores.TryGetValue(key, out List<string>? list)) return null;
        
        List<SealedSecretValue<TAttribute, TProtected>> store = [];
        SecretSerializer serializer = new();
        foreach (string line in list) store.Add(serializer.Deserialize<TAttribute, TProtected>(line));

        return store;
    }

    public static async Task<VaultData> Deserialize(Stream stream)
    {
        using StreamReader reader = new(stream, leaveOpen: true);
        string? clientLine = await reader.ReadLineAsync();
        if (clientLine == null) throw new ArgumentException("Invalid vault format", nameof(stream));

        List<VaultClientEntry> clients = JsonSerializer.Deserialize<List<VaultClientEntry>>(clientLine) ??
            throw new ArgumentException("Invalid vault format", nameof(stream));

        string? currentType = null;
        List<string> entries = [];
        Dictionary<string, List<string>> typedVaults = [];
        while (await reader.ReadLineAsync() is string line)
            if (line.StartsWith('{'))
            {
                entries.Add(line);
            }
            else
            {
                if (currentType != null)
                {
                    typedVaults.Add(currentType, entries);
                    entries = [];
                }
                else
                {
                    throw new ArgumentException("Invalid vault format", nameof(stream));
                }
            }

        if (currentType != null) typedVaults.Add(currentType, entries);

        return new VaultData(clients, typedVaults);
    }

    public async Task Serialize(Stream stream)
    {
        await using StreamWriter writer = new(stream, leaveOpen: true);
        await writer.WriteLineAsync(JsonSerializer.Serialize(_clients));
        foreach ((string type, List<string> data) in _typedStores)
        {
            await writer.WriteLineAsync(type);
            foreach (string line in data) await writer.WriteLineAsync(line);
        }
    }

    public bool HasPublicKey(Guid clientId)
    {
        return _clients.Any(c => c.ClientId == clientId);
    }

    public ImmutableArray<byte> GetPublicKey(Guid clientId)
    {
        return _clients.FirstOrDefault(c => c.ClientId == clientId)?.PublicKey ?? throw new KeyNotFoundException();
    }
}