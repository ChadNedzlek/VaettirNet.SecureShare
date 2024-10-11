using System;
using System.Buffers;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare;

public delegate TOut SpanFunc<TIn, out TOut>(TIn span, out int cb)
    where TIn : allows ref struct;
public delegate TOut SpanFunc<TIn, in TState, out TOut>(TIn span, TState state, out int cb)
    where TState : allows ref struct
    where TIn : allows ref struct;

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

public readonly ref struct SpanTuple<T1, T2>
{
    public readonly Span<T1> Span1;
    public readonly Span<T2> Span2;

    public SpanTuple(Span<T1> span1, Span<T2> span2)
    {
        Span1 = span1;
        Span2 = span2;
    }

    public void Deconstruct(out Span<T1> span1, out Span<T2> span2)
    {
        span1 = Span1;
        span2 = Span2;
    }
}

public readonly ref struct ReadOnlySpanTuple<T1, T2>
{
    public readonly ReadOnlySpan<T1> Span1;
    public readonly ReadOnlySpan<T2> Span2;

    public ReadOnlySpanTuple(ReadOnlySpan<T1> span1, ReadOnlySpan<T2> span2)
    {
        Span1 = span1;
        Span2 = span2;
    }

    public void Deconstruct(out ReadOnlySpan<T1> span1, out ReadOnlySpan<T2> span2)
    {
        span1 = Span1;
        span2 = Span2;
    }
}

public readonly ref struct ReadOnlySpanTuple<T1, T2, T3>
{
    public readonly ReadOnlySpan<T1> Span1;
    public readonly ReadOnlySpan<T2> Span2;
    public readonly ReadOnlySpan<T3> Span3;

    public ReadOnlySpanTuple(ReadOnlySpan<T1> span1, ReadOnlySpan<T2> span2, ReadOnlySpan<T3> span3)
    {
        Span1 = span1;
        Span2 = span2;
        Span3 = span3;
    }

    public void Deconstruct(out ReadOnlySpan<T1> span1, out ReadOnlySpan<T2> span2, out ReadOnlySpan<T3> span3)
    {
        span1 = Span1;
        span2 = Span2;
        span3 = Span3;
    }
}

public static class SpanTuple
{
    public static SpanTuple<T1, T2> Create<T1, T2>(Span<T1> span1, Span<T2> span2) => new(span1, span2);
    public static ReadOnlySpanTuple<T1, T2> Create<T1, T2>(ReadOnlySpan<T1> span1, ReadOnlySpan<T2> span2) => new(span1, span2);
    public static ReadOnlySpanTuple<T1, T2, T3> Create<T1, T2, T3>(ReadOnlySpan<T1> span1, ReadOnlySpan<T2> span2, ReadOnlySpan<T3> span3) => new(span1, span2, span3);
}

public readonly ref struct SpanTupleWithState<T1, T2, TOther>
{
    public readonly Span<T1> Span1;
    public readonly Span<T2> Span2;
    public readonly TOther Other;
    
    public SpanTupleWithState(Span<T1> span1, Span<T2> span2, TOther other)
    {
        Span1 = span1;
        Span2 = span2;
        Other = other;
    }
    
    public void Deconstruct(out Span<T1> span1, out Span<T2> span2, out TOther other)
    {
        other = Other;
        span1 = Span1;
        span2 = Span2;
    }
}

internal static class Helpers
{
    internal static RentedSpan<T> GrowingSpan<T>(Span<T> startSpan, in SpanFunc<Span<T>, bool> callback, ArrayPool<T> pool, Func<int,int>? growth = null)
    {
        growth ??= x => x << 2;
        if (callback(startSpan, out int cb))
        {
            return new RentedSpan<T>(startSpan[..cb]);
        }

        int size = startSpan.Length;
        while (true)
        {
            size = growth(size);
            T[] rented = pool.Rent(size);
            if (callback(rented, out cb))
            {
                return new RentedSpan<T>(rented.AsSpan(0, cb), rented, pool);
            }
            pool.Return(rented);
        }
    }
    internal static RentedSpan<T> GrowingSpan<T, TState>(Span<T> startSpan, in SpanFunc<Span<T>, TState, bool> callback, TState state, ArrayPool<T> pool, Func<int,int>? growth = null)
        where TState : allows ref struct
    {
        growth ??= x => x << 2;
        if (callback(startSpan, state, out int cb))
        {
            return new RentedSpan<T>(startSpan[..cb]);
        }

        int size = startSpan.Length;
        while (true)
        {
            size = growth(size);
            T[] rented = pool.Rent(size);
            if (callback(rented, state, out cb))
            {
                return new RentedSpan<T>(rented.AsSpan(0, cb), rented, pool);
            }
            pool.Return(rented);
        }
    }
}