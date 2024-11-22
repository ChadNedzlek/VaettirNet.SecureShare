using System;
using System.Collections;
using System.Collections.Generic;
using ProtoBuf;

namespace VaettirNet.SecureShare.Secrets;

[ProtoContract(SkipConstructor = true)]
public class UntypedSealedSecret : IEquatable<UntypedSealedSecret>
{
    [ProtoMember(1)]
    public Guid Id { get; private set; }

    [ProtoMember(5)]
    public uint Version { get; private set; }

    [ProtoMember(6)]
    public ReadOnlyMemory<byte> HashBytes { get; private set; }

    public UntypedSealedSecret(Guid id, uint version, ReadOnlyMemory<byte> hashBytes)
    {
        Id = id;
        Version = version;
        HashBytes = hashBytes;
    }

    public class Comparer : IComparer<UntypedSealedSecret>, IComparer
    {
        private static readonly Comparer<Guid?> s_comparer = Comparer<Guid?>.Default;
        public static Comparer Instance { get; } = new();

        public int Compare(UntypedSealedSecret? x, UntypedSealedSecret? y) => s_comparer.Compare(x?.Id, y?.Id);
        public int Compare(object? x, object? y) => s_comparer.Compare((x as UntypedSealedSecret)?.Id, (y as UntypedSealedSecret)?.Id);
    }

    public virtual bool Equals(UntypedSealedSecret? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        return Id.Equals(other.Id) && Version == other.Version && HashBytes.Span.SequenceEqual(other.HashBytes.Span);
    }

    public override bool Equals(object? obj)
    {
        if (obj is null) return false;
        if (ReferenceEquals(this, obj)) return true;
        if (obj.GetType() != GetType()) return false;
        return Equals((UntypedSealedSecret)obj);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Id, Version, HashBytes);
    }
}