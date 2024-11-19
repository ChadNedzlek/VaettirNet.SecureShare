using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryWriter<TWriter>
    where TWriter : IBufferWriter<byte>, allows ref struct
{
    private PackedBinarySerializer _serializer;
    private TWriter _writer;

    public PackedBinaryWriter(PackedBinarySerializer serializer, TWriter writer)
    {
        _serializer = serializer;
        _writer = writer;
    }

#nullable disable
    private delegate int WriteCoreDelegate(ref PackedBinaryWriter<TWriter> writer, object value, PackedBinarySerializationContext ctx);
    
    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public int Write(Type type, object value, PackedBinarySerializationContext ctx)
    {
        return typeof(PackedBinaryWriter<TWriter>)
            .GetMethod(nameof(WriteCore), BindingFlags.NonPublic | BindingFlags.Static)!
            .MakeGenericMethod(type)
            .CreateDelegate<WriteCoreDelegate>()
            .Invoke(ref this, value, ctx);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public int Write<T>(T value, PackedBinarySerializationContext ctx)
    {
        return WriteCore(ref this, value, ctx);
    }

    private static int WriteCore<T>(ref PackedBinaryWriter<TWriter> writer, T value, PackedBinarySerializationContext ctx)
    {
        if (typeof(T) == typeof(void))
        {
            return 0;
        }

        if (typeof(T) == typeof(byte))
        {
            return writer.WriteByte((byte)(object)value, ctx);
        }

        if (typeof(T) == typeof(sbyte))
        {
            return writer.WriteSByte((sbyte)(object)value, ctx);
        }
        
        if (typeof(T) == typeof(short))
        {
            return writer.WriteInt16((short)(object)value, ctx);
        }

        if (typeof(T) == typeof(ushort))
        {
            return writer.WriteUInt16((ushort)(object)value, ctx);
        }

        if (typeof(T) == typeof(int))
        {
            return writer.WriteInt32((int)(object)value, ctx);
        }

        if (typeof(T) == typeof(uint))
        {
            return writer.WriteUInt32((uint)(object)value, ctx);
        }

        if (typeof(T) == typeof(long))
        {
            return writer.WriteInt64((long)(object)value, ctx);
        }

        if (typeof(T) == typeof(ulong))
        {
            return writer.WriteUInt64((ulong)(object)value, ctx);
        }

        if (typeof(T) == typeof(float))
        {
            return writer.WriteSingle((float)(object)value, ctx);
        }

        if (typeof(T) == typeof(double))
        {
            return writer.WriteDouble((double)(object)value, ctx);
        }

        if (typeof(T) == typeof(string))
        {
            return writer.WriteString((string)(object)value, ctx);
        }

        if (typeof(T) == typeof(bool))
        {
            return writer.WriteBool((bool)(object)value, ctx);
        }

        if (typeof(T) == typeof(char))
        {
            return writer.WriteChar((char)(object)value, ctx);
        }

        if (!typeof(T).IsValueType)
        {
            return writer.WriteRefValue<T>(value, ctx);
        }

        if (typeof(T).IsGenericType && typeof(T).GetGenericTypeDefinition() == typeof(ReadOnlyMemory<>))
        {
            return writer.WriteRecastReadOnlyMemory(value, ctx);
        }
        
        if (typeof(T).IsGenericType && typeof(T).GetGenericTypeDefinition() == typeof(Memory<>))
        {
            return writer.WriteRecastMemory(value, ctx);
        }
        
        if (typeof(T).IsGenericType && typeof(T).GetGenericTypeDefinition() == typeof(ReadOnlySpan<>))
        {
            return writer.WriteRecastReadOnlySpan(value, ctx);
        }

        writer.ThrowUnknownType(typeof(T));
        return default;
    }

    private int WriteRefValue<T>(object value, PackedBinarySerializationContext ctx)
    {
        if (TryWriteArray<T>(value, ctx, out int written)) return written;
        
        if (TryWriteEnumerable<T>(value, ctx, out written)) return written;
        
        if (TryWriteSerializable<T>(value, ctx, out written)) return written;
        
        if (TryWriteWithMetadata<T>(value, ctx, out written)) return written;

        if (typeof(T).GetCustomAttribute<PackedBinarySerializableAttribute>() is { } attr)
        {
        }

        ThrowUnknownType(typeof(T));
        return default;
    }

    private static readonly ReflectionDelegate s_serializableReflector = new(nameof(WriteSerializable));

    private static int WriteSerializable(ref PackedBinaryWriter<TWriter> writer, IPackedBinarySerializable value, PackedBinarySerializationContext ctx)
    {
        return writer.WriteSerializable(value, ctx);
    }
    
    public int WriteSerializable<T>(T value, PackedBinarySerializationContext ctx) where T:IPackedBinarySerializable
    {
        int written = 0;
        if (!typeof(T).IsValueType)
        {
            written = WriteBool(value is not null, ctx);
            if (value is null)
            {
                return 1;
            }
        }
        
        return written + value.Write(ref this, ctx);
    }

    private bool TryWriteSerializable<T>(object value, PackedBinarySerializationContext ctx, out int written)
    {
        if (typeof(T).IsAssignableTo(typeof(IPackedBinarySerializable)))
        {
            written = s_serializableReflector.GetSerializer<IPackedBinarySerializable>(typeof(T)).Invoke(ref this, (IPackedBinarySerializable)value, ctx);
            return true;
        }

        written = 0;
        return false;
    }

    [DoesNotReturn]
    private void ThrowUnknownType(Type type)
    {
        throw new ArgumentException($"Type {type.FullName} is not serializable", nameof(type));
    }
}