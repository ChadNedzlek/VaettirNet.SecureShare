using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Text;
using VaettirNet.PackedBinarySerialization.Buffers;

namespace VaettirNet.PackedBinarySerialization;

public record class PackedBinarySerializationOptions(Encoding? Encoding = null, bool UsePackedEncoding = false, bool ImplicitRepeat = false);

public class PackedBinarySerializer
{
    private PackedBinarySerializationContext BuildContext(PackedBinarySerializationOptions? options)
    {
        if (options == null)
            return default;
        return new PackedBinarySerializationContext(options.Encoding, default, options.ImplicitRepeat, options.UsePackedEncoding);
    }

    public void Serialize<T>(Stream s, T value, PackedBinarySerializationOptions? options = null)
    {
        PipeWriter writer = PipeWriter.Create(s);
        SerializeCore(ref writer, value, BuildContext(options));
    }

    private void SerializeCore<TWriter, T>(ref TWriter writer, T value, PackedBinarySerializationContext ctx)
        where TWriter : IBufferWriter<byte>
    {
        new PackedBinaryWriter<TWriter>(this, writer).Write(value, ctx);
    }
    
    private void SerializeCore<TWriter, T>(ref TWriter writer, Type type, T value, PackedBinarySerializationContext ctx)
        where TWriter : IBufferWriter<byte>
    {
        new PackedBinaryWriter<TWriter>(this, writer).Write(type, value, ctx);
    }

    public void Serialize<T>(IBufferWriter<byte> b, T value, PackedBinarySerializationOptions? options = null)
    {
        SerializeCore(ref b, value, BuildContext(options));
    }
    
    public void Serialize(Stream s, Type type, object value, PackedBinarySerializationOptions? options = null)
    {
        PipeWriter writer = PipeWriter.Create(s);
        SerializeCore(ref writer, value, BuildContext(options));
        writer.Complete();
    }

    public void Serialize(IBufferWriter<byte> b, Type type, object value, PackedBinarySerializationOptions? options = null)
    {
        SerializeCore(ref b, value, BuildContext(options));
    }

    public T Deserialize<T>(Stream stream, PackedBinarySerializationOptions? options = null)
    {
        StreamBufferReader reader = new(stream);
        return DeserializeCore<T, StreamBufferReader>(ref reader, typeof(T), BuildContext(options));
    }

    public T Deserialize<T>(IBufferReader<byte> b, PackedBinarySerializationOptions? options = null)
    {
        return DeserializeCore<T, IBufferReader<byte>>(ref b, typeof(T), BuildContext(options));
    }
    
    public T Deserialize<T>(ReadOnlySpan<byte> b, PackedBinarySerializationOptions? options = null) where T:allows ref struct
    {
        SpanBufferReader<byte> reader = new(b);
        return DeserializeCore<T, SpanBufferReader<byte>>(ref reader, typeof(T), BuildContext(options));
    }

    public object Deserialize(Stream stream, Type type, PackedBinarySerializationOptions? options = null)
    {
        StreamBufferReader reader = new(stream);
        return DeserializeCore<object, StreamBufferReader>(ref reader, type, BuildContext(options));
    }

    public object Deserialize(IBufferReader<byte> b, Type type, PackedBinarySerializationOptions? options = null)
    {
        return DeserializeCore<object, IBufferReader<byte>>(ref b, type, BuildContext(options));
    }
    
    private T DeserializeCore<T, TReader>(scoped ref TReader reader, Type type, PackedBinarySerializationContext ctx)
        where TReader : IBufferReader<byte>, allows ref struct
        where T : allows ref struct
    {
        return new PackedBinaryReader<TReader>(this, reader).Read<T>(type, ctx);
    }
    
    public int MetadataRevision { get; private set; } = 1;

    private readonly Dictionary<Type, Dictionary<int, Type>> _tagToType = [];
    private readonly Dictionary<Type, Dictionary<Type, int>> _typeToTag = [];
    
    public Dictionary<Type, int>? GetSubtypeTags(Type baseClass)
    {
        return _typeToTag.GetValueOrDefault(baseClass);
    }
    public Dictionary<int, Type>? GetTagSubtypes(Type baseClass)
    {
        return _tagToType.GetValueOrDefault(baseClass);
    }
    
    public PackedBinarySerializer AddSubType<TBase, TDerived>(int tag) => AddSubType(typeof(TBase), typeof(TDerived), tag);
    public PackedBinarySerializer AddSubType(Type baseClass, Type derived, int tag)
    {
        MetadataRevision++;
        _tagToType.GetOrAdd(baseClass).Add(tag, derived);
        _typeToTag.GetOrAdd(baseClass).Add(derived, tag);
        return this;
    }
}

internal static class DictionaryExtensions
{
    public static TValue GetOrAdd<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, Func<TKey, TValue> create)
    {
        if (!dictionary.TryGetValue(key, out TValue? value))
        {
            dictionary.Add(key, value = create(key));
        }

        return value;
    }
    public static TValue GetOrAdd<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key) where TValue : new()
    {
        if (!dictionary.TryGetValue(key, out TValue? value))
        {
            dictionary.Add(key, value = new());
        }

        return value;
    }
}