using System;
using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;

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

    private delegate int WriteSurrogateDelegate<in TModel>(
        ref PackedBinaryWriter<TWriter> writer,
        TModel value,
        Delegate transform,
        PackedBinarySerializationContext ctx
    );

    private static int WriteSurrogate<TModel, TSurrogate>(
        ref PackedBinaryWriter<TWriter> writer,
        TModel value,
        Delegate transform,
        PackedBinarySerializationContext ctx
    )
    {
        var typedTransform = (Func<TModel, TSurrogate>)transform;
        return writer.Write(typedTransform(value), ctx);
    }

    private static int WriteCore<T>(ref PackedBinaryWriter<TWriter> writer, T value, PackedBinarySerializationContext ctx)
    {
        if (typeof(T) == typeof(void))
        {
            return 0;
        }

        if (typeof(T) == typeof(byte))
        {
            return writer.WriteByte(ReflectionHelpers.As<T, byte>(value), ctx);
        }

        if (typeof(T) == typeof(sbyte))
        {
            return writer.WriteSByte(ReflectionHelpers.As<T, sbyte>(value), ctx);
        }
        
        if (typeof(T) == typeof(short))
        {
            return writer.WriteInt16(ReflectionHelpers.As<T, short>(value), ctx);
        }

        if (typeof(T) == typeof(ushort))
        {
            return writer.WriteUInt16(ReflectionHelpers.As<T, ushort>(value), ctx);
        }

        if (typeof(T) == typeof(int))
        {
            return writer.WriteInt32(ReflectionHelpers.As<T, int>(value), ctx);
        }

        if (typeof(T) == typeof(uint))
        {
            return writer.WriteUInt32(ReflectionHelpers.As<T, uint>(value), ctx);
        }

        if (typeof(T) == typeof(long))
        {
            return writer.WriteInt64(ReflectionHelpers.As<T, long>(value), ctx);
        }

        if (typeof(T) == typeof(ulong))
        {
            return writer.WriteUInt64(ReflectionHelpers.As<T, ulong>(value), ctx);
        }

        if (typeof(T) == typeof(float))
        {
            return writer.WriteSingle(ReflectionHelpers.As<T, float>(value), ctx);
        }

        if (typeof(T) == typeof(double))
        {
            return writer.WriteDouble(ReflectionHelpers.As<T, double>(value), ctx);
        }

        if (typeof(T) == typeof(string))
        {
            return writer.WriteString(ReflectionHelpers.As<T, string>(value), ctx);
        }

        if (typeof(T) == typeof(bool))
        {
            return writer.WriteBool(ReflectionHelpers.As<T, bool>(value), ctx);
        }

        if (typeof(T) == typeof(char))
        {
            return writer.WriteChar(ReflectionHelpers.As<T, char>(value), ctx);
        }

        if (typeof(T) == typeof(Guid))
        {
            return writer.WriteGuid(ReflectionHelpers.As<T, Guid>(value), ctx);
        }

        if (typeof(T).IsEnum)
        {
            return writer.WriteEnum(value, ctx);
        }

        if (writer._serializer.TryGetWriteSurrogate(typeof(T), out var targetType, out var transformDelegate))
        {
            return typeof(PackedBinaryWriter<TWriter>)
                .GetMethod(nameof(WriteSurrogate), BindingFlags.Static | BindingFlags.NonPublic)!
                .MakeGenericMethod(typeof(T), targetType)
                .CreateDelegate<WriteSurrogateDelegate<T>>()
                .Invoke(ref writer, value, transformDelegate, ctx);
        }

        if (!typeof(T).IsValueType)
        {
            return writer.WriteRefValue<T>(value, ctx);
        }

        if (typeof(T).IsGenericType)
        {
            Type genericTypeDefinition = typeof(T).GetGenericTypeDefinition();
            if (genericTypeDefinition == typeof(ReadOnlyMemory<>))
            {
                return writer.WriteRecastReadOnlyMemory(value, ctx);
            }
        
            if (genericTypeDefinition == typeof(Memory<>))
            {
                return writer.WriteRecastMemory(value, ctx);
            }
        
            if (genericTypeDefinition == typeof(ReadOnlySpan<>))
            {
                return writer.WriteRecastReadOnlySpan(value, ctx);
            }
        }

        writer.ThrowUnknownType(typeof(T));
        return default;
    }

    private int WriteRefValue<T>(object value, PackedBinarySerializationContext ctx)
    {
        ref T refT = ref Unsafe.As<object,T>(ref value);
        
        if (TryWriteArray<T>(refT, ctx, out int written)) return written;
        if (TryWriteEnumerable<T>(refT, ctx, out written)) return written;
        if (TryWriteSerializable<T>(refT, ctx, out written)) return written;
        if (TryWriteWithMetadata<T>(refT, ctx, out written)) return written;

        ThrowUnknownType(typeof(T));
        return default;
    }

    private static readonly WriteReflectionDelegate s_serializableReflector = new(nameof(WriteSerializable));

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