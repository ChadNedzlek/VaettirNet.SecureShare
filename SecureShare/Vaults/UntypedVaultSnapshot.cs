using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using ProtoBuf;
using VaettirNet.SecureShare.Secrets;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract(SkipConstructor = true)]
public class UntypedVaultSnapshot : IComparable<UntypedVaultSnapshot>, IComparable
{

    [ProtoMember(1)]
    public VaultIdentifier Id { get; private set; }

    [ProtoMember(2)]
    private ImmutableSortedSet<UntypedSealedSecret>? _secrets;
    public ImmutableSortedSet<UntypedSealedSecret> Secrets => _secrets ?? [];

    [ProtoMember(3)]
    private ImmutableSortedSet<RemovedSecretRecord>? _removedSecrets;
    public ImmutableSortedSet<RemovedSecretRecord> RemovedSecrets => _removedSecrets ?? [];

    public UntypedVaultSnapshot(VaultIdentifier id, IEnumerable<UntypedSealedSecret>? secrets, IEnumerable<RemovedSecretRecord>? removedSecrets)
    {
        Id = id;
        _secrets = secrets?.ToImmutableSortedSet(UntypedSealedSecret.Comparer.Instance) ?? [];
        _removedSecrets = removedSecrets?.ToImmutableSortedSet(RemovedSecretRecord.Comparer.Instance) ?? [];
    }

    public int CompareTo(UntypedVaultSnapshot? other)
    {
        if (ReferenceEquals(this, other)) return 0;
        if (other is null) return 1;
        return Id.CompareTo(other.Id);
    }

    public int CompareTo(object? obj)
    {
        if (obj is null) return 1;
        if (ReferenceEquals(this, obj)) return 0;
        return obj is UntypedVaultSnapshot other ? CompareTo(other) : throw new ArgumentException($"Object must be of type {nameof(UntypedVaultSnapshot)}");
    }

    public OneOf<UntypedSealedSecret, RemovedSecretRecord> GetSecretEntry(Guid id)
    {
        if (TryGetSecretEntry(id, out var entry))
        {
            return entry;
        }

        throw new KeyNotFoundException();
    }
    
    public bool TryGetSecretEntry(Guid id, out OneOf<UntypedSealedSecret, RemovedSecretRecord> value)
    {
        if (Secrets.FirstOrDefault(s => s.Id == id) is { } secret)
        {
            value = secret;
            return true;
        }
        if (RemovedSecrets.FirstOrDefault(s => s.Id == id) is { } removed)
        {
            value = removed;
            return true;
        }

        value = default;
        return false;
    }
}