using System;
using System.Collections.Generic;

namespace TreeFormat;

public abstract class VaultNode
{
    private readonly List<VaultNode> _children = [];

    public VaultNode(VaultNode? parent, ReadOnlyMemory<byte> signature, int index)
    {
        Parent = parent;
        Signature = signature;
        Index = index;
        parent?._children.Add(this);
    }

    public ReadOnlyMemory<byte> Signature { get; }
    public IReadOnlyList<VaultNode> Children => _children.AsReadOnly();

    public VaultNode? Parent { get; }

    public int Index { get; }

    public override int GetHashCode()
    {
        HashCode hashCode = new();
        hashCode.AddBytes(Signature.Span);
        return hashCode.ToHashCode();
    }

    private bool Equals(VaultNode other)
    {
        return Signature.Span.SequenceEqual(other.Signature.Span);
    }

    public override bool Equals(object? obj)
    {
        if (obj is null) return false;
        if (ReferenceEquals(this, obj)) return true;
        if (obj.GetType() != GetType()) return false;
        return Equals((VaultNode)obj);
    }

    public abstract NodeValue GetValue();
}

public class VaultNode<T> : VaultNode
    where T : NodeValue
{
    public VaultNode(VaultNode? parent, T value, ReadOnlyMemory<byte> signature, int index) : base(parent, signature, index)
    {
        Value = value;
    }

    public VaultNode(VaultNode? parent, T value, ReadOnlyMemory<byte> signature) : this(parent, value, signature, -1)
    {
    }

    public T Value { get; }

    public override NodeValue GetValue()
    {
        return Value;
    }
}