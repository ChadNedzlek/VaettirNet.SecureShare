using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace VaettirNet.SecureShare.Common;

public readonly struct OneOf<T1, T2> : IEquatable<OneOf<T1, T2>>
{
    private readonly T1? _item1;
    private readonly T2? _item2;
    private readonly bool _second;

    public OneOf(T1 item)
    {
        _item1 = item;
    }

    public OneOf(T2 item)
    {
        _second = true;
        _item2 = item;
    }

    public void Map(Action<T1> a, Action<T2> b)
    {
        if (_second) b(_item2!);
        else a(_item1!);
    }
    
    public T Map<T>(Func<T1, T> a, Func<T2, T> b)
    {
        return _second ? b(_item2!) : a(_item1!);
    }
    
    public OneOf<TA, TB> Map<TA, TB>(Func<T1, TA> a, Func<T2, TB> b)
    {
        return _second ? new(b(_item2!)) : new(a(_item1!));
    }

    public static implicit operator OneOf<T1, T2>(T1 item) => new(item);
    public static implicit operator OneOf<T1, T2>(T2 item) => new(item);

    public bool Is<T>() => Is<T>(out _);
    
    public bool Is<T>([NotNullWhen(true)] out T value)
    {
        if (_second)
        {
            if (typeof(T) == typeof(T2))
            {
                value = (T)(object)_item2!;
                return true;
            }

            value = default!;
            return false;
        }
        
        if (typeof(T) == typeof(T1))
        {
            value = (T)(object)_item1!;
            return true;
        }

        value = default!;
        return false;
    }

    public T As<T>()
    {
        if (Is(out T value)) return value;
        throw new ArgumentException("OneOf is not of specified type", nameof(T));
    }

    public bool Equals(OneOf<T1, T2> other)
    {
        return _second == other._second && EqualityComparer<T1?>.Default.Equals(_item1, other._item1) && EqualityComparer<T2?>.Default.Equals(_item2, other._item2);
    }
    
    public bool Equals(T1 other)
    {
        return !_second && EqualityComparer<T1?>.Default.Equals(_item1, other);
    }
    
    public bool Equals(T2 other)
    {
        return _second && EqualityComparer<T2?>.Default.Equals(_item2, other);
    }

    public override bool Equals(object? obj)
    {
        return obj switch
        {
            T1 t1 => Equals(t1),
            T2 t2 => Equals(t2),
            OneOf<T1, T2> one => Equals(one),
            _ => false,
        };
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(_item1, _item2, _second);
    }

    public static bool operator ==(OneOf<T1, T2> left, OneOf<T1, T2> right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(OneOf<T1, T2> left, OneOf<T1, T2> right)
    {
        return !(left == right);
    }
}