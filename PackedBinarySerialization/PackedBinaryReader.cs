using System;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryReader<TReader>
    where TReader : IBufferReader<byte>, allows ref struct
{
    private PackedBinarySerializer _serializer;
    private TReader _reader;

    public PackedBinaryReader(PackedBinarySerializer serializer, TReader reader)
    {
        _serializer = serializer;
        _reader = reader;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public T Read<T>(PackedBinarySerializationContext ctx) => Read<T>(typeof(T), ctx);

    private delegate TOut ReadSurrogateDelegate<out TOut>(
        scoped ref PackedBinaryReader<TReader> reader,
        Delegate transform,
        PackedBinarySerializationContext ctx
    )
        where TOut : allows ref struct;

    private static TOut WriteSurrogate<TModel, TSurrogate, TOut>(
        scoped ref PackedBinaryReader<TReader> reader,
        Delegate transform,
        PackedBinarySerializationContext ctx
    )
        where TOut : allows ref struct
    {
        var typedTransform = (Func<TSurrogate, TModel>)transform;
        return ReflectionHelpers.As<TModel, TOut>(typedTransform(reader.Read<TSurrogate>(ctx)));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public T Read<T>(Type type, PackedBinarySerializationContext ctx)
        where T : allows ref struct
    {
        if (type == typeof(void))
        {
            return default!;
        }

        if (type == typeof(sbyte))
        {
            return ReflectionHelpers.As<sbyte, T>(ReadSByte(ctx));
        }

        if (type == typeof(short))
        {
            return ReflectionHelpers.As<short, T>(ReadInt16(ctx));
        }

        if (type == typeof(int))
        {
            return ReflectionHelpers.As<int, T>(ReadInt32(ctx));
        }

        if (type == typeof(long))
        {
            return ReflectionHelpers.As<long, T>(ReadInt64(ctx));
        }

        if (type == typeof(byte))
        {
            return ReflectionHelpers.As<byte, T>(ReadByte(ctx));
        }

        if (type == typeof(ushort))
        {
            return ReflectionHelpers.As<ushort, T>(ReadUInt16(ctx));
        }

        if (type == typeof(uint))
        {
            return ReflectionHelpers.As<uint, T>(ReadUInt32(ctx));
        }

        if (type == typeof(ulong))
        {
            return ReflectionHelpers.As<ulong, T>(ReadUInt64(ctx));
        }

        if (type == typeof(float))
        {
            return ReflectionHelpers.As<float, T>(ReadSingle(ctx));
        }

        if (type == typeof(double))
        {
            return ReflectionHelpers.As<double, T>(ReadDouble(ctx));
        }

        if (type == typeof(string))
        {
            return ReflectionHelpers.As<string, T>(ReadString(ctx)!);
        }

        if (type == typeof(bool))
        {
            return ReflectionHelpers.As<bool, T>(ReadBool(ctx));
        }

        if (type == typeof(char))
        {
            return ReflectionHelpers.As<char, T>(ReadChar(ctx));
        }

        if (type == typeof(Guid))
        {
            return ReflectionHelpers.As<Guid, T>(ReadGuid(ctx));
        }

        if (type.IsEnum)
        {
            return ReadEnum<T>(ctx);
        }

        if (_serializer.TryGetReadSurrogate(type, out Type? targetType, out Delegate? transform))
        {
            return GetMember<ReadSurrogateDelegate<T>>(nameof(WriteSurrogate), type, targetType, typeof(T))
                .Invoke(ref this, transform, ctx);
        }

        if (!type.IsValueType)
        {
            object? refValue = ReadRefType(type, ctx);
            if (refValue is null)
                return default!;
            
            return ReflectionHelpers.As<object?, T>(refValue);
        }

        if (type.IsGenericType)
        {
            Type genericTypeDefinition = type.GetGenericTypeDefinition();
            if (genericTypeDefinition == typeof(Memory<>))
            {
                return ReadRecastMemory<T>(ctx);
            }

            if (genericTypeDefinition == typeof(ReadOnlyMemory<>))
            {
                return ReadRecastReadOnlyMemory<T>(ctx);
            }

            if (genericTypeDefinition == typeof(ImmutableArray<>))
            {
                return ReadRecastImmutableArray<T>(ctx);
            }
        }

        ThrowUnknownType(type);
        return default;
    }

    public ReadOnlySpan<byte> GetSpan(int sizeHint) => _reader.GetSpan(sizeHint);
    public void Advance(int consumed) => _reader.Advance(consumed);

    [DoesNotReturn]
    private void ThrowUnknownType(Type type)
    {
        throw new ArgumentException($"Type {type.FullName} is not serializable", nameof(type));
    }

    public object? ReadRefType(Type type, PackedBinarySerializationContext ctx)
    {
        if (TryReadArray(type, ctx, out object? written)) return written;
        if (TryReadList(type, ctx, out written)) return written;
        if (TryReadSerializable(type, ctx, out written)) return written;
        if (TryReadFromMetadata(type, ctx, out written)) return written;
        if (TryReadImmutableList(type, ctx, out written)) return written;
        if (TryReadImmutableSortedSet(type, ctx, out written)) return written;
            
        ThrowUnknownType(type);
        return default;
    }

    private ReflectionDelegate s_serializable = new ReflectionDelegate(nameof(ReadSerializable));
    
    private bool TryReadSerializable(Type type, PackedBinarySerializationContext ctx, out object? written)
    {
        if (type.GetInterfaces()
                .Where(i => i.IsGenericType)
                .FirstOrDefault(i => i.GetGenericTypeDefinition() == typeof(IPackedBinarySerializable<>)) is {} serializable)
        {
            written = s_serializable.GetSerializer<object>(serializable).Invoke(ref this, ctx);
            return true;
        }

        written = null;
        return false;
    }
    
    private static T ReadSerializable<T>(ref PackedBinaryReader<TReader> reader, PackedBinarySerializationContext ctx)
        where T : IPackedBinarySerializable<T> =>
        reader.ReadSerializable<T>(ctx);

    public T ReadSerializable<T>(PackedBinarySerializationContext ctx)
        where T : IPackedBinarySerializable<T>
    {
        if (!typeof(T).IsValueType)
        {
            bool nonNull = ReadBool(ctx);
            if (!nonNull)
            {
                return default!;
            }
        }

        return T.Read(ref this, ctx);
    }
}