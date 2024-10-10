using System;
using System.Buffers;

namespace SecureShare;

public static class Helpers
{
    public static RentedSpan<T> GrowingSpan<T>(Span<T> startSpan, in SpanFunc<T, bool> callback, ArrayPool<T> pool, Func<int,int>? growth = null)
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
}