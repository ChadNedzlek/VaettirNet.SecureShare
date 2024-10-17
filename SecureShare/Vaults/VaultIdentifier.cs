using System;
using ProtoBuf;

namespace VaettirNet.SecureShare.Vaults;

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