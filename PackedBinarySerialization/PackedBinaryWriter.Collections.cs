using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Runtime.CompilerServices;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryWriter<TWriter>
{
    private static readonly WriteReflectionDelegate s_readOnlySpanDelegates = new(
        nameof(WriteRecastReadOnlySpan),
        t => [t, t.GetGenericArguments()[0]]
    );

    private int WriteRecastReadOnlySpan<TSpan>(TSpan span, PackedBinarySerializationContext ctx)
    {
        return s_readOnlySpanDelegates.GetSerializer<TSpan>(typeof(TSpan)).Invoke(ref this, span, ctx);
    }

    private static int WriteRecastReadOnlySpan<TSpan, TElement>(
        ref PackedBinaryWriter<TWriter> writer,
        TSpan span,
        PackedBinarySerializationContext ctx
    )
    {
        ref ReadOnlySpan<TElement> s = ref Unsafe.As<TSpan, ReadOnlySpan<TElement>>(ref span);
        return writer.WriteSpan(s, ctx);
    }

    private static readonly WriteReflectionDelegate s_spanDelegates = new(nameof(WriteRecastSpan), t => [t, t.GetGenericArguments()[0]]);

    private int WriteRecastSpan<TSpan>(TSpan span, PackedBinarySerializationContext ctx)
    {
        return s_spanDelegates.GetSerializer<TSpan>(typeof(TSpan)).Invoke(ref this, span, ctx);
    }

    private static int WriteRecastSpan<TSpan, TElement>(
        ref PackedBinaryWriter<TWriter> writer,
        TSpan span,
        PackedBinarySerializationContext ctx
    )
    {
        ref Span<TElement> s = ref Unsafe.As<TSpan, Span<TElement>>(ref span);
        return writer.WriteSpan((ReadOnlySpan<TElement>)s, ctx);
    }

    private int WriteRecastReadOnlyMemory<TMemory>(TMemory value, PackedBinarySerializationContext ctx)
    {
        return s_memoryDelegates.GetSerializer<TMemory>(typeof(TMemory)).Invoke(ref this, value, ctx);
    }

    private static readonly WriteReflectionDelegate s_memoryDelegates = new(nameof(WriteRecastMemory), t => [t, t.GetGenericArguments()[0]]);

    private int WriteRecastMemory<TMemory>(TMemory value, PackedBinarySerializationContext ctx)
    {
        return s_memoryDelegates.GetSerializer<TMemory>(typeof(TMemory)).Invoke(ref this, value, ctx);
    }

    private static int WriteRecastMemory<TSpan, TElement>(
        ref PackedBinaryWriter<TWriter> writer,
        TSpan span,
        PackedBinarySerializationContext ctx
    )
    {
        ref Memory<TElement> s = ref Unsafe.As<TSpan, Memory<TElement>>(ref span);
        return writer.WriteSpan((ReadOnlySpan<TElement>)s.Span, ctx);
    }

    public int WriteMemory<T>(ReadOnlyMemory<T> value, PackedBinarySerializationContext ctx)
    {
        return WriteSpan(value.Span, ctx);
    }

    public int WriteSpan<T>(ReadOnlySpan<T> value, PackedBinarySerializationContext ctx)
    {
        int written = WriteInt32(value.Length, ctx with { UsePackedIntegers = true });
        foreach (T item in value) written += Write(item, ctx);

        return written;
    }

    private static readonly WriteReflectionDelegate s_arrayReflector = new(nameof(WriteArray), a => [a.GetElementType()]);

    private static int WriteArray<T>(ref PackedBinaryWriter<TWriter> writer, Array value, PackedBinarySerializationContext ctx)
    {
        return writer.WriteArray((T[])value, ctx);
    }

    public int WriteArray<T>(T[]? value, PackedBinarySerializationContext ctx)
    {
        PackedBinarySerializationContext itemContext = ctx.Descend();
        if (ctx.ImplicitSize)
        {
            if (value is null || value.Length == 0)
                return 0;

            int written = 0;
            foreach (T item in value) written += Write(item, itemContext);

            return written;
        }
        else
        {
            if (value is null) return WriteInt32(-1, ctx with { UsePackedIntegers = true });

            int written = WriteInt32(value.Length, ctx with { UsePackedIntegers = true });
            foreach (T item in value) written += Write(item, itemContext);

            return written;
        }
    }

    private static readonly WriteReflectionDelegate s_enumerableReflector = new(nameof(WriteEnumerable));

    private static int WriteEnumerable<T>(ref PackedBinaryWriter<TWriter> writer, IEnumerable value, PackedBinarySerializationContext ctx)
    {
        return writer.WriteEnumerable((IEnumerable<T>)value, ctx);
    }

    public int WriteEnumerable<T>(IEnumerable<T>? value, PackedBinarySerializationContext ctx)
    {
        PackedBinarySerializationContext itemContext = ctx.Descend();
        if (ctx.ImplicitSize)
        {
            if (value == null) return 0;

            int written = 0;
            foreach (T item in value) written += Write(item, itemContext);

            return written;
        }
        else
        {
            if (value == null) return WriteInt32(-1, ctx with { UsePackedIntegers = true });

            T[] array = value.ToArray();
            int written = WriteInt32(array.Length, ctx with { UsePackedIntegers = true });
            foreach (T item in array) written += Write(item, itemContext);

            return written;
        }
    }

    private bool TryWriteEnumerable<T>(object value, PackedBinarySerializationContext ctx, out int written)
    {
        if (typeof(T).GetInterfaces()
                .Concat([typeof(T)])
                .FirstOrDefault(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IEnumerable<>)) is { } ienumerable)
        {
            written = s_enumerableReflector.GetSerializer<IEnumerable>(ienumerable).Invoke(ref this, (IEnumerable)value, ctx);
            return true;
        }

        written = 0;
        return false;
    }

    private bool TryWriteArray<T>(object value, PackedBinarySerializationContext ctx, out int written)
    {
        if (typeof(T).IsSZArray)
        {
            written = s_arrayReflector.GetSerializer<Array>(typeof(T)).Invoke(ref this, (Array)value, ctx);
            return true;
        }

        written = 0;
        return false;
    }
    
    private static readonly WriteReflectionDelegate s_immutableArrayDelegates = new(
        nameof(WriteRecastImmutableArray),
        t => [t, t.GetGenericArguments()[0]]
    );

    private int WriteRecastImmutableArray<T>(T array, PackedBinarySerializationContext ctx)
    {
        return s_immutableArrayDelegates.GetSerializer<T>(typeof(T)).Invoke(ref this, array, ctx);
    }

    private static int WriteRecastImmutableArray<TArray, TElement>(
        ref PackedBinaryWriter<TWriter> writer,
        TArray array,
        PackedBinarySerializationContext ctx
    )
    {
        ref ImmutableArray<TElement> arr = ref Unsafe.As<TArray, ImmutableArray<TElement>>(ref array);
        return writer.WriteSpan(arr.AsSpan(), ctx);
    }
}