using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ProtoBuf;
using ProtoBuf.Meta;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract]
public class VaultDataSnapshot : BinarySerializable<VaultDataSnapshot>
{
    [ProtoMember(1)]
    public required ImmutableList<VaultClientEntry> Clients { get; init; }
    [ProtoMember(2)]
    public required ImmutableList<BlockedVaultClientEntry> BlockedClients { get; init; }
    [ProtoMember(3)]
    public required ImmutableList<Signed<ClientModificationRecord>> ClientModificications { get; init; }
    [ProtoMember(4)]
    [ProtoMap]
    public required ImmutableDictionary<VaultIdentifier, UntypedVaultSnapshot> Vaults { get; init; }
    [ProtoMember(5)]
    public required ReadOnlyMemory<byte> ManifestSignature { get; init; }
}

public class VaultSnapshotSerializer
{
    private readonly ProtobufObjectSerializer<VaultDataSnapshot> _serializer;

    public VaultSnapshotSerializer(params IEnumerable<Type> sealedSecretTypes)
    {
        _serializer = ProtobufObjectSerializer<VaultDataSnapshot>.Create(
            model =>
            {
                AddSignedType<ClientModificationRecord>(model);
                AddSignedType<RemovedSecretRecord>(model);
                var sealedValueType = model.Add<UntypedSealedValue>();
                int fieldNumber = 20;
                foreach (Type type in sealedSecretTypes)
                {
                    sealedValueType.AddSubType(fieldNumber++, type).UseConstructor = false;
                }

                void AddSignedType<T>(RuntimeTypeModel runtimeTypeModel)
                    where T : ISignable<T>
                {
                    runtimeTypeModel.Add<Signed<T>>();
                }
            }
        );
    }

    public void Serialize(Stream destination, VaultDataSnapshot snapshot)
    {
        _serializer.Serialize(destination, snapshot);
    }

    public VaultDataSnapshot Deserialize(Stream source)
    {
        return _serializer.Deserialize(source);
    }

    public static Builder CreateBuilder() => new Builder(ImmutableList<Type>.Empty);

    public class Builder
    {
        public readonly ImmutableList<Type> SecretTypes;

        public Builder(ImmutableList<Type> secretTypes)
        {
            SecretTypes = secretTypes;
        }

        public Builder WithSecret<TAttribute, TProtected>()
            where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute>
            where TProtected : IBinarySerializable<TProtected>
        {
            return new Builder(SecretTypes.Add(typeof(SealedSecretValue<TAttribute, TProtected>)));
        }

        public VaultSnapshotSerializer Build()
        {
            return new VaultSnapshotSerializer(SecretTypes);
        }
    }
}

[ProtoContract]
public class UntypedVaultSnapshot
{
    [ProtoMember(1)]
    public required ImmutableList<UntypedSealedValue> Secrets { get; init; }
    [ProtoMember(2)]
    public required ImmutableList<Signed<RemovedSecretRecord>> RemovedSecrets { get; init; }
}

[ProtoContract]
public class RemovedSecretRecord : BinarySerializable<RemovedSecretRecord>, ISignable<RemovedSecretRecord>
{
    [ProtoMember(1)]
    public required Guid Id { get; init; }
    [ProtoMember(2)]
    public required uint Version { get; init; }
    [ProtoMember(3)]
    public required ReadOnlyMemory<byte> Signature { get; init; }
    [ProtoMember(4)]
    public required Guid Authorizer { get; init; }
}

[ProtoContract]
public class VaultIdentifier : IComparable<VaultIdentifier>, IEquatable<VaultIdentifier>, IComparable
{
    [ProtoMember(1)]
    public required string Name{ get; init; }

    [ProtoMember(2)]
    public required string AttributeType{ get; init; }

    [ProtoMember(3)]
    public required string ProtectedType{ get; init; }

    public static VaultIdentifier Create<TAttribute, TProtected>() => new VaultIdentifier
    {
        Name = NameFromTypes<TAttribute, TProtected>(), AttributeType = typeof(TAttribute).FullName!, ProtectedType = typeof(TProtected).FullName!
    };

    private static string NameFromTypes(Type attributeType, Type prot) => attributeType.FullName + '|' + prot.FullName;
    private static string NameFromTypes<TAttribute, TProtected>() => NameFromTypes(typeof(TAttribute), typeof(TProtected));

    public bool Equals(VaultIdentifier? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        return Name == other.Name && AttributeType == other.AttributeType && ProtectedType == other.ProtectedType;
    }

    public override bool Equals(object? obj)
    {
        if (obj is null) return false;
        if (ReferenceEquals(this, obj)) return true;
        if (obj.GetType() != GetType()) return false;
        return Equals((VaultIdentifier)obj);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Name, AttributeType, ProtectedType);
    }

    public int CompareTo(VaultIdentifier? other)
    {
        if (ReferenceEquals(this, other)) return 0;
        if (other is null) return 1;
        int nameComparison = string.Compare(Name, other.Name, StringComparison.Ordinal);
        if (nameComparison != 0) return nameComparison;
        int attributeTypeComparison = string.Compare(AttributeType, other.AttributeType, StringComparison.Ordinal);
        if (attributeTypeComparison != 0) return attributeTypeComparison;
        return string.Compare(ProtectedType, other.ProtectedType, StringComparison.Ordinal);
    }

    public int CompareTo(object? obj)
    {
        if (obj is null) return 1;
        if (ReferenceEquals(this, obj)) return 0;
        return obj is VaultIdentifier other ? CompareTo(other) : throw new ArgumentException($"Object must be of type {nameof(VaultIdentifier)}");
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