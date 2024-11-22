using System;
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static TOut As<TIn, TOut>(TIn value)
        where TOut : allows ref struct
    {
        ref TOut refVale = ref Unsafe.As<TIn, TOut>(ref value);
        return refVale;
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
            return As<sbyte, T>(ReadSByte(ctx));
        }

        if (type == typeof(short))
        {
            return As<short, T>(ReadInt16(ctx));
        }

        if (type == typeof(int))
        {
            return As<int, T>(ReadInt32(ctx));
        }

        if (type == typeof(long))
        {
            return As<long, T>(ReadInt64(ctx));
        }

        if (type == typeof(byte))
        {
            return As<byte, T>(ReadByte(ctx));
        }

        if (type == typeof(ushort))
        {
            return As<ushort, T>(ReadUInt16(ctx));
        }

        if (type == typeof(uint))
        {
            return As<uint, T>(ReadUInt32(ctx));
        }

        if (type == typeof(ulong))
        {
            return As<ulong, T>(ReadUInt64(ctx));
        }

        if (type == typeof(float))
        {
            return As<float, T>(ReadSingle(ctx));
        }

        if (type == typeof(double))
        {
            return As<double, T>(ReadDouble(ctx));
        }

        if (type == typeof(string))
        {
            return As<string, T>(ReadString(ctx)!);
        }

        if (type == typeof(bool))
        {
            return As<bool, T>(ReadBool(ctx));
        }

        if (type == typeof(char))
        {
            return As<char, T>(ReadChar(ctx));
        }

        if (!type.IsValueType)
        {
            object? refValue = ReadRefType(type, ctx);
            if (refValue is null)
                return default!;
            
            return As<object?, T>(refValue);
        }

        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Memory<>))
        {
            return ReadRecastMemory<T>(ctx);
        }

        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ReadOnlyMemory<>))
        {
            return ReadRecastReadOnlyMemory<T>(ctx);
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