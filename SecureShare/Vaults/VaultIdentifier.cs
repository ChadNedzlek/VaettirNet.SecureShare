using System;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.SecureShare.Vaults;

[PackedBinarySerializable]
public class VaultIdentifier : IComparable<VaultIdentifier>, IEquatable<VaultIdentifier>, IComparable
{
    [PackedBinaryMember(1)]
    public string Name{ get; private set; }

    [PackedBinaryMember(2)]
    public string AttributeTypeName{ get; private set; }

    [PackedBinaryMember(3)]
    public string ProtectedTypeName{ get; private set; }
    
    public VaultIdentifier(string name, string attributeTypeName, string protectedTypeName)
    {
        Name = name;
        AttributeTypeName = attributeTypeName;
        ProtectedTypeName = protectedTypeName;
    }

    public static VaultIdentifier Create<TAttribute, TProtected>() => new(
        NameFromTypes<TAttribute, TProtected>(),
        typeof(TAttribute).FullName!,
        typeof(TProtected).FullName!
    );
    
    public static VaultIdentifier Create<TAttribute, TProtected>(string name) => new(
        name ?? NameFromTypes<TAttribute, TProtected>(),
        typeof(TAttribute).FullName!,
        typeof(TProtected).FullName!
    );
    
    public static VaultIdentifier Create(string name, Type attributeType, Type protectedType) => new(
        name ?? NameFromTypes(attributeType, protectedType),
        attributeType.FullName!,
        protectedType.FullName!
    );
    
    public static VaultIdentifier Create(Type attributeType, Type protectedType) => new(
        NameFromTypes(attributeType, protectedType),
        attributeType.FullName!,
        protectedType.FullName!
    );

    private static string NameFromTypes(Type attributeType, Type protectedType) => attributeType.FullName + '|' + protectedType.FullName;
    private static string NameFromTypes<TAttribute, TProtected>() => NameFromTypes(typeof(TAttribute), typeof(TProtected));

    public bool Equals(VaultIdentifier other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        return Name == other.Name && AttributeTypeName == other.AttributeTypeName && ProtectedTypeName == other.ProtectedTypeName;
    }

    public override bool Equals(object obj)
    {
        if (obj is null) return false;
        if (ReferenceEquals(this, obj)) return true;
        if (obj.GetType() != GetType()) return false;
        return Equals((VaultIdentifier)obj);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Name, AttributeTypeName, ProtectedTypeName);
    }

    public int CompareTo(VaultIdentifier other)
    {
        if (ReferenceEquals(this, other)) return 0;
        if (other is null) return 1;
        return string.Compare(Name, other.Name, StringComparison.Ordinal);
    }

    public int CompareTo(object obj)
    {
        if (obj is null) return 1;
        if (ReferenceEquals(this, obj)) return 0;
        return obj is VaultIdentifier other ? CompareTo(other) : throw new ArgumentException($"Object must be of type {nameof(VaultIdentifier)}");
    }
    
    
}