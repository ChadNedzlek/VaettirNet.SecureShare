using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryWriter<TWriter>
{
    private static readonly ReflectionDelegate s_readOnlySpanDelegates = new(nameof(WriteRecastReadOnlySpan), t => [t, t.GetGenericArguments()[0]]);

    private int WriteRecastReadOnlySpan<TSpan>(TSpan span, PackedBinarySerializationContext ctx) => 
        s_readOnlySpanDelegates.GetSerializer<TSpan>(typeof(TSpan)).Invoke(ref this, span, ctx);

    private static int WriteRecastReadOnlySpan<TSpan, TElement>(
        ref PackedBinaryWriter<TWriter> writer,
        TSpan span,
        PackedBinarySerializationContext ctx
    )
    {
        ref var s = ref Unsafe.As<TSpan, ReadOnlySpan<TElement>>(ref span);
        return writer.WriteSpan(s, ctx);
    }
    
    private static readonly ReflectionDelegate s_spanDelegates = new(nameof(WriteRecastSpan), t => [t, t.GetGenericArguments()[0]]);

    private int WriteRecastSpan<TSpan>(TSpan span, PackedBinarySerializationContext ctx) => 
        s_spanDelegates.GetSerializer<TSpan>(typeof(TSpan)).Invoke(ref this, span, ctx);

    private static int WriteRecastSpan<TSpan, TElement>(
        ref PackedBinaryWriter<TWriter> writer,
        TSpan span,
        PackedBinarySerializationContext ctx
    )
    {
        ref Span<TElement> s = ref Unsafe.As<TSpan, Span<TElement>>(ref span);
        return writer.WriteSpan((ReadOnlySpan<TElement>)s, ctx);
    }
    
    private static readonly ReflectionDelegate s_readOnlyMemoryDelegates = new(nameof(WriteRecastReadOnlyMemory), t => [t, t.GetGenericArguments()[0]]);

    private int WriteRecastReadOnlyMemory<TMemory>(TMemory value, PackedBinarySerializationContext ctx) =>
        s_memoryDelegates.GetSerializer<TMemory>(typeof(TMemory)).Invoke(ref this, value, ctx);

    private static int WriteRecastReadOnlyMemory<TSpan, TElement>(
        ref PackedBinaryWriter<TWriter> writer,
        TSpan span,
        PackedBinarySerializationContext ctx
    )
    {
        ref var s = ref Unsafe.As<TSpan, ReadOnlyMemory<TElement>>(ref span);
        return writer.WriteSpan(s.Span, ctx);
    }
    
    private static readonly ReflectionDelegate s_memoryDelegates = new(nameof(WriteRecastMemory), t => [t, t.GetGenericArguments()[0]]);

    private int WriteRecastMemory<TMemory>(TMemory value, PackedBinarySerializationContext ctx) =>
        s_memoryDelegates.GetSerializer<TMemory>(typeof(TMemory)).Invoke(ref this, value, ctx);

    private static int WriteRecastMemory<TSpan, TElement>(
        ref PackedBinaryWriter<TWriter> writer,
        TSpan span,
        PackedBinarySerializationContext ctx
    )
    {
        ref var s = ref Unsafe.As<TSpan, Memory<TElement>>(ref span);
        return writer.WriteSpan((ReadOnlySpan<TElement>)s.Span, ctx);
    }

    public int WriteMemory<T>(ReadOnlyMemory<T> value, PackedBinarySerializationContext ctx) => WriteSpan(value.Span, ctx);

    public int WriteSpan<T>(ReadOnlySpan<T> value, PackedBinarySerializationContext ctx)
    {
        int written = WriteInt32(value.Length, ctx with { UsePackedIntegers = true });
        foreach (var item in value)
        {
            written += Write(item, ctx);
        }

        return written;
    }

    private static readonly ReflectionDelegate s_arrayReflector = new(nameof(WriteArray), a => [a.GetElementType()]);

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
            foreach (var item in value)
            {
                written += Write(item, itemContext);
            }

            return written;
        }
        else
        {
            if (value is null || value.Length == 0)
            {
                return WriteInt32(0, ctx with {UsePackedIntegers = true});
            }
            
            int written = WriteInt32(value.Length, ctx with { UsePackedIntegers = true });
            foreach (var item in value)
            {
                written += Write(item, itemContext);
            }

            return written;
        }
    }

    private static readonly ReflectionDelegate s_enumerableReflector = new(nameof(WriteEnumerable));

    private static int WriteEnumerable<T>(ref PackedBinaryWriter<TWriter> writer, IEnumerable value, PackedBinarySerializationContext ctx)
    {
        return writer.WriteEnumerable((IEnumerable<T>)value, ctx);
    }
    
    public int WriteEnumerable<T>(IEnumerable<T>? value, PackedBinarySerializationContext ctx)
    {
        PackedBinarySerializationContext itemContext = ctx.Descend();
        if (ctx.ImplicitSize)
        {
            if (value == null)
            {
                return 0;
            }

            int written = 0;
            foreach (var item in value)
            {
                written += Write(item, itemContext);
            }

            return written;
        }
        else
        {
            if (value == null)
            {
                return WriteInt32(0, ctx with { UsePackedIntegers = true });
            }
            
            var array = value.ToArray();
            int written = WriteInt32(array.Length, ctx with { UsePackedIntegers = true });
            foreach (var item in array)
            {
                written += Write(item, itemContext);
            }

            return written;
        }
    }

    private bool TryWriteEnumerable<T>(object value, PackedBinarySerializationContext ctx, out int written)
    {
        if (typeof(T).GetInterfaces().Concat([typeof(T)]).FirstOrDefault(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IEnumerable<>)) is { } ienumerable)
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
}