using System;
using System.Collections.Generic;

namespace VaettirNet.TreeFormat;

public class BufferComparer : IEqualityComparer<ReadOnlyMemory<byte>>
{
    public static readonly BufferComparer Instance = new();

    private BufferComparer()
    {
    }

    public bool Equals(ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y)
    {
        return x.Span.SequenceEqual(y.Span);
    }

    public int GetHashCode(ReadOnlyMemory<byte> obj)
    {
        HashCode hashCode = new();
        hashCode.AddBytes(obj.Span);
        return hashCode.ToHashCode();
    }
}