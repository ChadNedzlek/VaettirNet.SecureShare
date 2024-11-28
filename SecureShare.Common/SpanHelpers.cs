using System;
using System.Buffers;
using JetBrains.Annotations;

namespace VaettirNet.SecureShare.Common;

public static class SpanHelpers
{
    [MustDisposeResource]
    public static RentedSpan<T> GrowingSpan<T>(Span<T> startSpan, SpanFunc<Span<T>, bool> callback, ArrayPool<T> pool, Func<int,int>? growth = null)
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
    public static RentedSpan<T> GrowingSpan<T, TState>(
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