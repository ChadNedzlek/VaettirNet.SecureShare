using System;
using System.Buffers;

namespace VaettirNet.SecureShare.Common;

public readonly ref struct RentedSpan<T>
{
    public RentedSpan(Span<T> span)
    {
        Span = span;
    }

    public RentedSpan(Span<T> span, T[] toReturn, ArrayPool<T> pool)
    {
        Span = span;
        _toReturn = toReturn;
        _pool = pool;
    }

    public readonly Span<T> Span;
    private readonly T[]? _toReturn;
    private readonly ArrayPool<T>? _pool;

    public void Dispose()
    {
        if (_toReturn != null) _pool?.Return(_toReturn);
    }
}