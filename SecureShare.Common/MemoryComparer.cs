using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace VaettirNet.SecureShare.Common;

public class MemoryComparer<T> : IEqualityComparer<ReadOnlyMemory<T>>
{
    private readonly IEqualityComparer<T> _itemComparer;

    public static readonly MemoryComparer<T> Default = new();
    

    public MemoryComparer() : this(EqualityComparer<T>.Default)
    {
    }

    public MemoryComparer(IEqualityComparer<T> itemComparer)
    {
        _itemComparer = itemComparer;
    }

    public bool Equals(ReadOnlyMemory<T> x, ReadOnlyMemory<T> y)
    {
        if (x.Length != y.Length)
        {
            return false;
        }

        ReadOnlySpan<T> a = x.Span, b = y.Span;

        for (int i = 0; i < x.Length; i++)
        {
            if (!_itemComparer.Equals(a[i], b[i]))
            {
                return false;
            }
        }

        return true;
    }

    public int GetHashCode(ReadOnlyMemory<T> obj)
    {
        HashCode h = new();
        foreach(T i in obj.Span){
            h.Add(_itemComparer.GetHashCode(i));
        }
        return h.ToHashCode();
    }
}

public static class Reflections
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [StackTraceHidden]
    public static Type CurrentType()
    {
        StackFrame[] frames = new StackTrace().GetFrames();
        int i = 0;
        while (frames[i].GetMethod()?.DeclaringType == typeof(Reflections))
        {
            i++;
        }

        return frames[i].GetMethod()!.DeclaringType!;
    }
}