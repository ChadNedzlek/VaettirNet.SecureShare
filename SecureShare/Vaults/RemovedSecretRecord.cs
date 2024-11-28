using System;
using System.Collections;
using System.Collections.Generic;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Crypto;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[PackedBinarySerializable]
public class RemovedSecretRecord : BinarySerializable<RemovedSecretRecord>, IBinarySignable<RemovedSecretRecord>, IEquatable<RemovedSecretRecord>
{
    [PackedBinaryConstructor]
    public RemovedSecretRecord(Guid id, uint version, ReadOnlyMemory<byte> signature)
    {
        Id = id;
        Version = version;
        Signature = signature;
    }

    [PackedBinaryMember(1)]
    public Guid Id { get; }

    [PackedBinaryMember(2)]
    public uint Version { get; }

    [PackedBinaryMember(3)]
    public ReadOnlyMemory<byte> Signature { get; }

    public bool Equals(RemovedSecretRecord other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        return Id.Equals(other.Id);
    }

    public override bool Equals(object obj)
    {
        if (obj is null) return false;
        if (ReferenceEquals(this, obj)) return true;
        if (obj.GetType() != GetType()) return false;
        return Equals((RemovedSecretRecord)obj);
    }

    public override int GetHashCode()
    {
        return Id.GetHashCode();
    }

    public class Comparer : IComparer<RemovedSecretRecord>, IComparer, IEqualityComparer<RemovedSecretRecord>
    {
        private static readonly Comparer<Guid?> s_comparer = Comparer<Guid?>.Default;
        public static Comparer Instance { get; } = new();

        public int Compare(object x, object y)
        {
            return s_comparer.Compare((x as RemovedSecretRecord)?.Id, (y as RemovedSecretRecord)?.Id);
        }

        public int Compare(RemovedSecretRecord x, RemovedSecretRecord y)
        {
            return s_comparer.Compare(x?.Id, y?.Id);
        }

        public bool Equals(RemovedSecretRecord x, RemovedSecretRecord y)
        {
            if (ReferenceEquals(x, y)) return true;
            if (x is null) return false;
            if (y is null) return false;
            if (x.GetType() != y.GetType()) return false;
            return x.Id.Equals(y.Id);
        }

        public int GetHashCode(RemovedSecretRecord obj)
        {
            return obj.Id.GetHashCode();
        }
    }
}