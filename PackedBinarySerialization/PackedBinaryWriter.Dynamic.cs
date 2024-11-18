using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryWriter<TWriter>
{
    public bool TryWriteWithMetadata<T>(object value, PackedBinarySerializationContext ctx, out int written)
    {
        if (typeof(T).GetCustomAttribute<PackedBinarySerializableAttribute>() is { } attr)
        {
            written = WriteWithMetadataCore(value, ctx, attr);
            return true;
        }

        written = 0;
        return false;
    }

    public int WriteWithMetadata<T>(T value, PackedBinarySerializationContext ctx) =>
        WriteWithMetadataCore(value, ctx, typeof(T).GetCustomAttribute<PackedBinarySerializableAttribute>()!);

    private static readonly Dictionary<(Type serializer, Type valueType), (int revision, Delegate factory)> s_reflectionCache = [];
    private readonly ReaderWriterLockSlim s_reflectionLock = new();

    private delegate int WriteMetadataDelegate<T>(ref PackedBinaryWriter<TWriter> writer, T value, PackedBinarySerializationContext ctx);
    
    private int WriteWithMetadataCore<T>(T value, PackedBinarySerializationContext ctx, PackedBinarySerializableAttribute attr)
    {
        return GetMetadataWriteDelegate<T>(attr).Invoke(ref this, value, ctx);
    }

    private WriteMetadataDelegate<T> GetMetadataWriteDelegate<T>(PackedBinarySerializableAttribute attr)
    {
        s_reflectionLock.EnterReadLock();
        try
        {
            if (s_reflectionCache.TryGetValue((_serializer.GetType(), typeof(T)), out var (revision, writer))
            {
                return (WriteMetadataDelegate<T>)writer;
            }
        }
        finally
        {
            s_reflectionLock.ExitReadLock();
        }
        
        s_reflectionLock.EnterWriteLock();
        try
        {
            if (s_reflectionCache.TryGetValue(typeof(T), out var writer))
            {
                return (WriteMetadataDelegate<T>)writer;
            }

            WriteMetadataDelegate<T> typed = BuildMetadataWriteDelegate<T>(attr);
            s_reflectionCache.Add(typeof(T), typed);
            return typed;
        }
        finally
        {
            s_reflectionLock.ExitWriteLock();
        }
    }

    private WriteMetadataDelegate<T> BuildMetadataWriteDelegate<T>(PackedBinarySerializableAttribute attr)
    {
        throw new NotImplementedException();
    }
}