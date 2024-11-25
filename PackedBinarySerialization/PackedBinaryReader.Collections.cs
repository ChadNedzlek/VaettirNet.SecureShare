using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryReader<TReader>
{
    private static readonly ReflectionDelegate s_memory = new(nameof(ReadRecastMemory), t => [t, t.GetGenericArguments()[0]]);

    private TMemory ReadRecastMemory<TMemory>(PackedBinarySerializationContext ctx)
        where TMemory : allows ref struct
    {
        return s_memory.GetSerializer<TMemory>(typeof(TMemory)).Invoke(ref this, ctx);
    }

    private static TMemory ReadRecastMemory<TMemory, TElement>(ref PackedBinaryReader<TReader> writer, PackedBinarySerializationContext ctx)
    {
        Memory<TElement> span = writer.ReadMemory<TElement>(ctx);
        ref TMemory cast = ref Unsafe.As<Memory<TElement>, TMemory>(ref span);
        return cast;
    }

    public Memory<T> ReadMemory<T>(PackedBinarySerializationContext ctx)
    {
        int len = ReadInt32(new PackedBinarySerializationContext { UsePackedIntegers = true });
        if (len == 0)
            return null;

        T[] arr = new T[len];
        for (int i = 0; i < len; i++) arr[i] = Read<T>(ctx.Descend());

        return arr;
    }

    private static readonly ReflectionDelegate s_readOnlyMemory = new(nameof(ReadRecastReadOnlyMemory), t => [t, t.GetGenericArguments()[0]]);

    private TMemory ReadRecastReadOnlyMemory<TMemory>(PackedBinarySerializationContext ctx)
        where TMemory : allows ref struct
    {
        return s_readOnlyMemory.GetSerializer<TMemory>(typeof(TMemory)).Invoke(ref this, ctx);
    }

    private static TMemory ReadRecastReadOnlyMemory<TMemory, TElement>(ref PackedBinaryReader<TReader> writer, PackedBinarySerializationContext ctx)
    {
        ReadOnlyMemory<TElement> span = writer.ReadReadOnlyMemory<TElement>(ctx);
        ref TMemory cast = ref Unsafe.As<ReadOnlyMemory<TElement>, TMemory>(ref span);
        return cast;
    }

    public ReadOnlyMemory<T> ReadReadOnlyMemory<T>(PackedBinarySerializationContext ctx)
    {
        return ReadMemory<T>(ctx);
    }

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
            return ReadCollectionType<List<T>, T>(s => s is int size ? new List<T>(size) : [], (l, _, e) => l.Add(e), ctx)?.ToArray();

        return ReadCollectionType<T[], T>(s => s is int size ? new T[size] : [], (l, i, e) => l[i] = e, ctx);
    }

    private static readonly Type[] s_asListTypes =
    [
        typeof(List<>),
        typeof(IEnumerable<>),
        typeof(IList<>),
        typeof(IReadOnlyList<>),
        typeof(ICollection<>),
        typeof(IReadOnlyCollection<>)
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

    private static IEnumerable? ReadList<T>(ref PackedBinaryReader<TReader> reader, PackedBinarySerializationContext ctx)
    {
        return reader.ReadList<T>(ctx);
    }

    private IEnumerable? ReadList<T>(PackedBinarySerializationContext ctx)
    {
        return ReadCollectionType<List<T>, T>(s => s is int size ? new List<T>(size) : [], (l, _, e) => l.Add(e), ctx);
    }

    private TCollection? ReadCollectionType<TCollection, TElement>(
        Func<int?, TCollection> create,
        Action<TCollection, int, TElement> add,
        PackedBinarySerializationContext ctx
    )
    {
        PackedBinarySerializationContext descend = ctx.Descend();
        if (ctx.ImplicitSize)
        {
            TCollection l = create(null);
            int i = 0;
            while (!_reader.GetSpan(1).IsEmpty) add(l, i++, Read<TElement>(descend));
            return l;
        }

        {
            int len = ReadInt32(new PackedBinarySerializationContext { UsePackedIntegers = true });
            if (len == -1)
                return default;

            TCollection l = create(len);
            for (int i = 0; i < len; i++) add(l, i, Read<TElement>(descend));

            return l;
        }
    }

    private static readonly ReflectionDelegate s_immutableArray = new(nameof(ReadRecastImmutableArray), t => [t, t.GetGenericArguments()[0]]);

    private TArray ReadRecastImmutableArray<TArray>(PackedBinarySerializationContext ctx)
        where TArray : allows ref struct
    {
        return s_immutableArray.GetSerializer<TArray>(typeof(TArray)).Invoke(ref this, ctx);
    }

    private static TArray ReadRecastImmutableArray<TArray, TElement>(ref PackedBinaryReader<TReader> writer, PackedBinarySerializationContext ctx)
    {
        ImmutableArray<TElement> span = writer.ReadImmutableArray<TElement>(ctx);
        ref TArray cast = ref Unsafe.As<ImmutableArray<TElement>, TArray>(ref span);
        return cast;
    }

    public ImmutableArray<T> ReadImmutableArray<T>(PackedBinarySerializationContext ctx)
    {
        return ReadCollectionType<ImmutableArray<T>.Builder, T>(
                    s => s is int size ? ImmutableArray.CreateBuilder<T>(size) : ImmutableArray.CreateBuilder<T>(),
                    (a, _, e) => a.Add(e),
                    ctx
                )
                ?.ToImmutable() ??
            [];
    }

    private static readonly Type[] s_asImmutableListTypes =
    [
        typeof(ImmutableList<>),
        typeof(IImmutableList<>)
    ];

    private static readonly ReflectionDelegate s_immutableList = new(nameof(ReadRecastImmutableList), t => [t, t.GetGenericArguments()[0]]);

    private TList ReadRecastImmutableList<TList>(PackedBinarySerializationContext ctx)
        where TList : allows ref struct
    {
        return s_immutableList.GetSerializer<TList>(typeof(TList)).Invoke(ref this, ctx);
    }

    private static TList ReadRecastImmutableList<TList, TElement>(ref PackedBinaryReader<TReader> writer, PackedBinarySerializationContext ctx)
    {
        ImmutableList<TElement> span = writer.ReadImmutableList<TElement>(ctx);
        ref TList cast = ref Unsafe.As<ImmutableList<TElement>, TList>(ref span);
        return cast;
    }

    public ImmutableList<T> ReadImmutableList<T>(PackedBinarySerializationContext ctx)
    {
        return ReadCollectionType<ImmutableList<T>.Builder, T>(
                    _ => ImmutableList.CreateBuilder<T>(),
                    (a, _, e) => a.Add(e),
                    ctx
                )
                ?.ToImmutable() ??
            [];
    }

    private bool TryReadImmutableList(Type type, PackedBinarySerializationContext ctx, [MaybeNullWhen(false)] out object written)
    {
        if (type.IsGenericType && s_asImmutableListTypes.Contains(type.GetGenericTypeDefinition()))
        {
            written = s_immutableList.GetSerializer<object>(type).Invoke(ref this, ctx);
            return true;
        }

        written = null;
        return false;
    }

    private static readonly Type[] s_asImmutableSoredSetTypes =
    [
        typeof(ImmutableSortedSet<>)
    ];

    private static readonly ReflectionDelegate s_immutableSortedSet = new(nameof(ReadRecastImmutableSortedSet), t => [t, t.GetGenericArguments()[0]]);

    private TSortedSet ReadRecastImmutableSortedSet<TSortedSet>(PackedBinarySerializationContext ctx)
        where TSortedSet : allows ref struct
    {
        return s_immutableSortedSet.GetSerializer<TSortedSet>(typeof(TSortedSet)).Invoke(ref this, ctx);
    }

    private static TSortedSet ReadRecastImmutableSortedSet<TSortedSet, TElement>(
        ref PackedBinaryReader<TReader> writer,
        PackedBinarySerializationContext ctx
    )
    {
        ImmutableSortedSet<TElement> span = writer.ReadImmutableSortedSet<TElement>(ctx);
        ref TSortedSet cast = ref Unsafe.As<ImmutableSortedSet<TElement>, TSortedSet>(ref span);
        return cast;
    }

    public ImmutableSortedSet<T> ReadImmutableSortedSet<T>(PackedBinarySerializationContext ctx)
    {
        return ReadCollectionType<ImmutableSortedSet<T>.Builder, T>(
                    _ => ImmutableSortedSet.CreateBuilder<T>(),
                    (a, _, e) => a.Add(e),
                    ctx
                )
                ?.ToImmutable() ??
            [];
    }

    private bool TryReadImmutableSortedSet(Type type, PackedBinarySerializationContext ctx, out object? written)
    {
        if (type.IsGenericType && s_asImmutableSoredSetTypes.Contains(type.GetGenericTypeDefinition()))
        {
            written = s_immutableSortedSet.GetSerializer<object>(type).Invoke(ref this, ctx);
            return true;
        }

        written = null;
        return false;
    }
}