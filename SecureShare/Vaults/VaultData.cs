using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ProtoBuf;
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

public enum ClientAction
{
    None = 0,
    Added,
    Blocked,
    KeyChange,
}

[ProtoContract]
public class ClientModificationRecord : BinarySerializable<ClientModificationRecord>, ISignable<ClientModificationRecord>
{
    [ProtoMember(1)]
    public required ClientAction Action { get; init; }
    [ProtoMember(2)]
    public required Guid Client { get; init; }
    [ProtoMember(3)]
    public required ReadOnlyMemory<byte> SigningKey { get; init; }
    [ProtoMember(4)]
    public required ReadOnlyMemory<byte> EncryptionKey { get; init; }
    [ProtoMember(5)]
    public required Guid Authorizer { get; init; }
}