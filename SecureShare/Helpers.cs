using System;
using System.Buffers;
using JetBrains.Annotations;

namespace VaettirNet.SecureShare;

public delegate TOut SpanFunc<in TIn, out TOut>(TIn span, out int cb)
    where TIn : allows ref struct;

public delegate TOut SpanFunc<in TIn1, in TIn2, out TOut>(TIn1 span1, out int cb1, TIn2 span2, out int cb2)
    where TIn1 : allows ref struct
    where TIn2 : allows ref struct;

public delegate TOut SpanStateFunc<in TIn, in TState, out TOut>(TIn span, TState state, out int cb)
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

public readonly ref struct RefTuple<T1, T2> where T1 : allows ref struct where T2: allows ref struct
{
    public readonly T1 Item1;
    public readonly T2 Item2;

    public RefTuple(T1 item1, T2 item2)
    {
        Item1 = item1;
        Item2 = item2;
    }

    public void Deconstruct(out T1 span1, out T2 span2)
    {
        span1 = Item1;
        span2 = Item2;
    }
}

public readonly ref struct RefTuple<T1, T2, T3>
    where T1 : allows ref struct
    where T2: allows ref struct
    where T3: allows ref struct
{
    public readonly T1 Item1;
    public readonly T2 Item2;
    public readonly T3 Item3;

    public RefTuple(T1 item1, T2 item2, T3 item3)
    {
        Item1 = item1;
        Item2 = item2;
        Item3 = item3;
    }

    public void Deconstruct(out T1 item1, out T2 item2, out T3 item3)
    {
        item1 = Item1;
        item2 = Item2;
        item3 = Item3;
    }
}

public static class RefTuple
{
    public static RefTuple<T1, T2> Create<T1, T2>(T1 item1, T2 item2)
        where T1 : allows ref struct
        where T2 : allows ref struct
        => new(item1, item2);
    public static RefTuple<T1, T2, T3> Create<T1, T2, T3>(T1 item1, T2 item2, T3 item3)
        where T1 : allows ref struct
        where T2 : allows ref struct
        where T3 : allows ref struct
        => new(item1, item2, item3);
}

internal static class Helpers
{
    [MustDisposeResource]
    internal static RentedSpan<T> GrowingSpan<T>(Span<T> startSpan, SpanFunc<Span<T>, bool> callback, ArrayPool<T> pool, Func<int,int>? growth = null)
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
    
    [MustDisposeResource]
    internal static RentedSpan<T> GrowingSpan<T, TState>(
        Span<T> startSpan,
        TState state,
        SpanStateFunc<Span<T>, TState, bool> callback,
        ArrayPool<T> pool,
        Func<int, int>? growth = null)
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