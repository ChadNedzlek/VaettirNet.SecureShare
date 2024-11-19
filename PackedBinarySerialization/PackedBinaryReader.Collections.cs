using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryReader<TReader>
{
    private static readonly ReflectionDelegate s_memory = new(nameof(ReadRecastMemory), t => [t, t.GetGenericArguments()[0]]);

    private TMemory ReadRecastMemory<TMemory>(PackedBinarySerializationContext ctx)
        where TMemory : allows ref struct =>
        s_memory.GetSerializer<TMemory>(typeof(TMemory)).Invoke(ref this, ctx);

    private static TMemory ReadRecastMemory<TMemory, TElement>(ref PackedBinaryReader<TReader> writer, PackedBinarySerializationContext ctx)
    {
        var span = writer.ReadMemory<TElement>(ctx);
        ref var cast = ref Unsafe.As<Memory<TElement>, TMemory>(ref span);
        return cast;
    }

    public Memory<T> ReadMemory<T>(PackedBinarySerializationContext ctx)
    {
        int len = ReadInt32(new PackedBinarySerializationContext { UsePackedIntegers = true });
        if (len == 0)
            return null;
        
        T[] arr = new T[len];
        for (int i = 0; i < len; i++)
        {
            arr[i] = Read<T>(ctx.Descend());
        }

        return arr;
    }
    
    private static readonly ReflectionDelegate s_readOnlyMemory = new(nameof(ReadRecastReadOnlyMemory), t => [t, t.GetGenericArguments()[0]]);

    private TMemory ReadRecastReadOnlyMemory<TMemory>(PackedBinarySerializationContext ctx)
        where TMemory : allows ref struct =>
        s_readOnlyMemory.GetSerializer<TMemory>(typeof(TMemory)).Invoke(ref this, ctx);

    private static TMemory ReadRecastReadOnlyMemory<TMemory, TElement>(ref PackedBinaryReader<TReader> writer, PackedBinarySerializationContext ctx)
    {
        var span = writer.ReadReadOnlyMemory<TElement>(ctx);
        ref var cast = ref Unsafe.As<ReadOnlyMemory<TElement>, TMemory>(ref span);
        return cast;
    }

    public ReadOnlyMemory<T> ReadReadOnlyMemory<T>(PackedBinarySerializationContext ctx) => ReadMemory<T>(ctx);

    private static readonly ReflectionDelegate s_array = new(nameof(ReadArray), t => [t.GetElementType()!]);

    private bool TryReadArray(Type type, PackedBinarySerializationContext ctx, [MaybeNullWhen(false)] out object written)
    {
        if (type.IsSZArray)
        {
            written = s_array.GetSerializer<Array>(type).Invoke(ref this, ctx);
            return true;
        }

        written = null;
        return false;
    }
        
    private static T[]? ReadArray<T>(ref PackedBinaryReader<TReader> reader, PackedBinarySerializationContext ctx)
    {
        return reader.ReadArray<T>(ctx);
    }

    public T[]? ReadArray<T>(PackedBinarySerializationContext ctx)
    {
        if (ctx.ImplicitSize)
        {
            List<T> l = [];
            while (!_reader.GetSpan(1).IsEmpty)
            {
                l.Add(Read<T>(ctx.Descend()));
            }
            return l.ToArray();
        }

        int len = ReadInt32(new PackedBinarySerializationContext { UsePackedIntegers = true });
        if (len == -1)
            return null;
        
        T[] arr = new T[len];
        for (int i = 0; i < len; i++)
        {
            arr[i] = Read<T>(ctx.Descend());
        }

        return arr;
    }
    
    private static readonly Type[] s_asListTypes =
    [
        typeof(List<>),
        typeof(IEnumerable<>),
        typeof(IList<>),
        typeof(IReadOnlyList<>),
        typeof(ICollection<>),
        typeof(IReadOnlyCollection<>),
    ];
    
    private static readonly ReflectionDelegate s_list = new(nameof(ReadList), t => [t]);
    private bool TryReadList(Type type, PackedBinarySerializationContext ctx, out object? written)
    {
        if (type.IsGenericType && s_asListTypes.Contains(type.GetGenericTypeDefinition()))
        {
            written = s_list.GetSerializer<IEnumerable?>(type.GetGenericArguments()[0]).Invoke(ref this, ctx);
            return true;
        }

        written = null;
        return false;
    }
    
    private static IEnumerable? ReadList<T>(ref PackedBinaryReader<TReader> reader, PackedBinarySerializationContext ctx) => reader.ReadList<T>(ctx);

    private IEnumerable? ReadList<T>(PackedBinarySerializationContext ctx)
    {
        if (ctx.ImplicitSize)
        {
            List<T> l = [];
            while (!_reader.GetSpan(1).IsEmpty)
            {
                l.Add(Read<T>(ctx.Descend()));
            }
            return l;
        }

        {
            int len = ReadInt32(new PackedBinarySerializationContext { UsePackedIntegers = true });
            if (len == -1)
                return null;

            List<T> l = new(len);
            for (int i = 0; i < len; i++)
            {
                l.Add(Read<T>(ctx.Descend()));
            }

            return l;
        }
    }
}